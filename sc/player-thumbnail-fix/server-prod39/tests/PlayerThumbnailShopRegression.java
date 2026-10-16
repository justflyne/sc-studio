package savbrawl.server;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import savbrawl.logic.command.home.LogicGiveDeliveryItemsCommand;
import savbrawl.logic.data.DataTables;
import savbrawl.logic.data.DataType;
import savbrawl.logic.data.PlayerThumbnailData;
import savbrawl.logic.helper.ByteStreamHelper;
import savbrawl.logic.home.HomeMode;
import savbrawl.logic.home.gatcha.GatchaDrop;
import savbrawl.logic.home.items.Offer;
import savbrawl.logic.home.items.OfferBundle;
import savbrawl.logic.home.items.ShopItem;
import savbrawl.logic.listener.LogicGameListener;
import savbrawl.server.message.PiranhaMessage;
import savbrawl.server.message.home.AvailableServerCommandMessage;
import savbrawl.server.database.models.Account;
import savbrawl.server.utils.JsonUtil;
import savbrawl.titan.datastream.ByteStream;

public final class PlayerThumbnailShopRegression {
    private static int checks;
    private static void check(boolean value, String reason) {
        checks++;
        if (!value) throw new AssertionError(reason);
    }
    private static final class Listener extends LogicGameListener {
        final List<LogicGiveDeliveryItemsCommand> deliveries = new ArrayList<>();
        public void SendMessage(PiranhaMessage message) {
            if (message instanceof AvailableServerCommandMessage available
                && available.Command instanceof LogicGiveDeliveryItemsCommand delivery) {
                deliveries.add(delivery);
            }
        }
        public void SendTCPMessage(PiranhaMessage message) { SendMessage(message); }
    }
    private static void wire(Offer offer, int expectedIndex) {
        ByteStream encoded = new ByteStream(32);
        offer.Encode(encoded);
        encoded.WriteVInt(12345);
        ByteStream decoded = new ByteStream(encoded.GetByteArray(), encoded.GetLength());
        check(decoded.ReadVInt() == (offer.Type == null ? 0 : offer.Type.value), "reward type");
        check(decoded.ReadVInt() == offer.Count, "reward count");
        check(ByteStreamHelper.ReadDataReference(decoded) == offer.ItemDataId, "data reference retained");
        check(decoded.ReadVInt() == expectedIndex, "correct fourth reward value");
        check(decoded.ReadVInt() == 12345, "next reward remains aligned");
    }
    private static Offer thumbnail(int id) {
        return new Offer(ShopItem.PlayerThumbnail, 1, id);
    }
    private static OfferBundle bundle(int currency, Offer... items) {
        OfferBundle b = new OfferBundle();
        b.Items = new ArrayList<>(List.of(items));
        b.Currency = currency;
        b.Cost = 7;
        b.Claim = "thumbnail-regression";
        b.EndTime = Instant.now().plusSeconds(3600);
        return b;
    }
    private static Account account(OfferBundle b, Listener listener) {
        Account a = new Account();
        a.Avatar.Diamonds = 200;
        a.Avatar.Gold = 200;
        a.Avatar.StarPoints = 200;
        a.Home.OfferBundles.add(b);
        new HomeMode(a.Home, a.Avatar, listener);
        return a;
    }
    private static void purchase(int id, int currency) {
        Listener l = new Listener();
        OfferBundle b = bundle(currency, thumbnail(id));
        Account a = account(b, l);
        check(!a.Home.IsThumbnailUnlocked(id), "creator icon starts locked");
        a.Home.PurchaseOffer(0);
        check(a.Home.IsThumbnailUnlocked(id), "purchase unlocks requested icon");
        check(a.Home.UnlockedPlayerThumbnails.contains(id), "ownership retains full global ID");
        check(b.Purchased && a.Home.OffersClaimed.contains(b.Claim), "offer is claimed");
        check(a.Avatar.Diamonds == (currency == 0 ? 193 : 200), "diamond debit");
        check(a.Avatar.Gold == (currency == 1 ? 193 : 200), "gold debit");
        check(a.Avatar.StarPoints == (currency == 3 ? 193 : 200), "starpoint debit");
        check(l.deliveries.size() == 1, "one delivery command");
        LogicGiveDeliveryItemsCommand command = l.deliveries.get(0);
        check(command.DeliveryUnits.size() == 1, "one reward unit");
        GatchaDrop[] drops = command.DeliveryUnits.get(0).GetDrops();
        check(drops.length == 1 && drops[0].Type == 5 && drops[0].DataGlobalId == id
            && drops[0].Count == 1, "thumbnail delivery contains correct ID");
        ByteStream encoded = new ByteStream(64);
        drops[0].Encode(encoded);
        ByteStream decoded = new ByteStream(encoded.GetByteArray(), encoded.GetLength());
        check(decoded.ReadVInt() == 1 && ByteStreamHelper.ReadDataReference(decoded) == id
            && decoded.ReadVInt() == 5, "delivery wire contains full thumbnail reference");
        a.Home.PurchaseOffer(0);
        command.Execute(a.Home.HomeMode);
        check(l.deliveries.size() == 1, "repeat purchase rejected");
        check(a.Home.UnlockedPlayerThumbnails.stream().filter(n -> n == id).count() == 1,
            "repeat delivery does not duplicate ownership");
        check(a.Avatar.Diamonds == (currency == 0 ? 193 : 200), "repeat purchase cannot debit twice");
    }
    private static void rejected(Offer offer, boolean owned, boolean duplicate) {
        Listener l = new Listener();
        OfferBundle b = duplicate ? bundle(0, offer, thumbnail(offer.ItemDataId)) : bundle(0, offer);
        Account a = account(b, l);
        if (owned) a.Home.UnlockThumbnail(offer.ItemDataId);
        a.Home.PurchaseOffer(0);
        check(a.Avatar.Diamonds == 200, "invalid thumbnail cannot consume currency");
        check(!b.Purchased && !a.Home.OffersClaimed.contains(b.Claim), "invalid offer stays unclaimed");
        check(l.deliveries.isEmpty(), "invalid offer creates no delivery");
    }
    public static void main(String[] args) throws Exception {
        DataTables.Load(false);
        check(DataTables.Get(DataType.PlayerThumbnail).Count() == 80, "client/server thumbnail registry has 80 rows");
        for (int index : new int[]{78, 79}) {
            int id = 28000000 + index;
            PlayerThumbnailData data = DataTables.Get(DataType.PlayerThumbnail).GetDataByGlobalId(id);
            check(data != null && data.IconExportName.equals("player_icon_creator_" + (index - 75) + "_26"),
                "creator global ID matches SC export");
            wire(thumbnail(id), index);
            Offer differingSkin = thumbnail(id);
            differingSkin.SkinDataId = 999;
            wire(differingSkin, index);
            for (int currency : new int[]{0, 1, 3}) purchase(id, currency);
        }
        for (ShopItem type : ShopItem.values()) {
            if (type == ShopItem.PlayerThumbnail) continue;
            Offer other = new Offer(type, 2, 16000001, 456);
            wire(other, 456);
        }
        OfferBundle[] configured = JsonUtil.FromJson(Files.readString(Path.of("JSON/offers.json")), OfferBundle[].class);
        boolean found = false;
        for (OfferBundle b : configured) {
            if (b.Items == null) continue;
            for (Offer o : b.Items) {
                if (o.Type == ShopItem.PlayerThumbnail && o.ItemDataId == 28000078) {
                    wire(o, 78);
                    found = true;
                }
            }
        }
        check(found, "existing live offer JSON is accepted without schema changes");
        rejected(thumbnail(28000999), false, false);
        rejected(thumbnail(16000078), false, false);
        rejected(thumbnail(28000078), true, false);
        rejected(thumbnail(28000078), false, true);
        Offer zeroCount = thumbnail(28000078);
        zeroCount.Count = 0;
        rejected(zeroCount, false, false);
        Offer extraCount = thumbnail(28000078);
        extraCount.Count = 2;
        rejected(extraCount, false, false);
        Listener listener = new Listener();
        Account insufficient = account(bundle(0, thumbnail(28000078)), listener);
        insufficient.Avatar.Diamonds = 6;
        insufficient.Home.PurchaseOffer(0);
        check(insufficient.Avatar.Diamonds == 6 && listener.deliveries.isEmpty()
            && !insufficient.Home.IsThumbnailUnlocked(28000078), "insufficient funds grant nothing");
        System.out.println("PlayerThumbnailShopRegression: " + checks + " checks passed");
    }
}
