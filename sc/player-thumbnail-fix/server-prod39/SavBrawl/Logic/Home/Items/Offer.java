package savbrawl.logic.home.items;

import java.util.ArrayList;
import java.util.List;
import savbrawl.logic.data.helper.GlobalId;
import savbrawl.logic.helper.ByteStreamHelper;
import savbrawl.titan.datastream.ByteStream;

public class Offer {
    public transient ShopItem Type;
    public transient boolean IsTestItem;
    public int Count;
    public int ItemDataId;
    public int SkinDataId;
    public Offer() {
    }
    public Offer(ShopItem type, int count) {
        Type = type;
        Count = count;
    }
    public Offer(String type, int count) {
        setTypeName(type);
        Count = count;
    }
    public Offer(ShopItem type, int count, int itemGlobalId) {
        this(type, count);
        ItemDataId = itemGlobalId;
    }
    public Offer(ShopItem type, int count, int itemGlobalId, int skinGlobalId) {
        this(type, count, itemGlobalId);
        SkinDataId = skinGlobalId;
    }
    public String getTypeName() {
        if (IsTestItem) return ShopItem.TestItem.name();
        if (Type == null) return ShopItem.BigBox.name();
        return Type.name();
    }
    public void setTypeName(String value) {
        IsTestItem = "TestItem".equalsIgnoreCase(value);
        if (value == null) {
            Type = ShopItem.BigBox;
            return;
        }
        for (ShopItem item : ShopItem.values()) {
            if (item.name().equalsIgnoreCase(value)) {
                Type = item;
                return;
            }
        }
        Type = ShopItem.BigBox;
    }
    public void Encode(ByteStream stream) {
        stream.WriteVInt(Type == null ? 0 : Type.value);
        stream.WriteVInt(Count);
        ByteStreamHelper.WriteDataReference(stream, ItemDataId);
        // For type 25 the client reads a thumbnail row index from this slot.
        // JSON continues to use ItemDataId with the full table-28 global ID.
        stream.WriteVInt(Type == ShopItem.PlayerThumbnail && GlobalId.GetClassId(ItemDataId) == 28
            ? GlobalId.GetInstanceId(ItemDataId) : SkinDataId);
    }
}
