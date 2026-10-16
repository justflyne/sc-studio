package savbrawl.logic.home;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Locale;
import java.util.Objects;
import java.util.Random;
import java.util.Set;
import java.util.TreeSet;

import com.google.gson.annotations.SerializedName;

import savbrawl.logic.avatar.ClientAvatar;
import savbrawl.logic.avatar.HeroLoadoutSelection;
import savbrawl.logic.command.home.LogicDayChangedCommand;
import savbrawl.logic.command.home.LogicGiveDeliveryItemsCommand;
import savbrawl.logic.command.home.LogicOffersChangedCommand;
import savbrawl.logic.data.CardData;
import savbrawl.logic.data.CharacterData;
import savbrawl.logic.data.DataTables;
import savbrawl.logic.data.DataType;
import savbrawl.logic.data.EmoteData;
import savbrawl.logic.data.MilestoneData;
import savbrawl.logic.data.NameColorData;
import savbrawl.logic.data.PlayerThumbnailData;
import savbrawl.logic.data.SkinConfData;
import savbrawl.logic.data.SkinData;
import savbrawl.logic.data.helper.DataTable;
import savbrawl.logic.data.helper.GlobalId;
import savbrawl.logic.data.helper.LogicData;
import savbrawl.logic.data.reader.Row;
import savbrawl.logic.data.reader.Table;
import savbrawl.logic.helper.ByteStreamHelper;
import savbrawl.logic.home.gatcha.DeliveryUnit;
import savbrawl.logic.home.gatcha.GatchaDrop;
import savbrawl.logic.home.items.BattleLogEntry;
import savbrawl.logic.home.items.EventData;
import savbrawl.logic.home.items.Notification;
import savbrawl.logic.home.items.NotificationFactory;
import savbrawl.logic.home.items.Offer;
import savbrawl.logic.home.items.OfferBundle;
import savbrawl.logic.home.items.ShopItem;
import savbrawl.logic.home.items.TimedOffer;
import savbrawl.logic.home.quest.Quest;
import savbrawl.logic.home.quest.Quests;
import savbrawl.logic.home.quest.SpecialQuestStore;
import savbrawl.logic.home.ranked.LogicPlayerRewardData;
import savbrawl.logic.home.ranked.RankedSeasonProgress;
import savbrawl.logic.home.structures.Hero;
import savbrawl.server.message.home.AvailableServerCommandMessage;
import savbrawl.logic.settings.BrawlPassSeasonConfig;
import savbrawl.server.utils.JsonUtil;
import savbrawl.titan.datastream.ByteStream;
import savbrawl.titan.datastream.ChecksumEncoder;

public class ClientHome {
    public static final int DAILYOFFERS_COUNT = 6;
    public static final int RANKED_POINTS_PER_RANK = 1000;
    private static final Duration QUEST_REFRESH_TIME_UTC = Duration.ofHours(9);
    private static final Instant MIN_INSTANT = Instant.ofEpochSecond(-62135596800L);
    private static final Random SHARED_RANDOM = new Random();
    public static final int[] GoldPacksPrice = new int[]{20, 50, 140, 280};
    public static final int[] GoldPacksAmount = new int[]{150, 400, 1200, 2600};
    private static class QuestPreview {
        public int Reward;
        public boolean IsPremium;
        public QuestPreview(int reward, boolean isPremium) {
            Reward = reward;
            IsPremium = isPremium;
        }
    }
    private static final QuestPreview[] UPCOMING_REGULAR_QUEST_PREVIEW = new QuestPreview[]{
        new QuestPreview(500, false),
        new QuestPreview(250, false),
        new QuestPreview(250, false),
        new QuestPreview(250, true)
    };
    public long HomeId;
    public int ThumbnailId;
    public int NameColorId;
    public int CharacterId;
    public List<OfferBundle> OfferBundles;
    public List<OfferBundle> OfferBundles1;
    private boolean TestItemPowerFixed;
    public TimedOffer TimedOffer;
    public TimedOffer TimedOffer1;
    public int TrophiesReward;
    public int TokenReward;
    public int StarTokenReward;
    public int StarPointsGained;
    public int CoinsGained;
    public int PowerPlayTrophiesReward;
    public int DiamondsGained;
    public BigInteger BrawlPassProgress;
    public BigInteger PremiumPassProgress;
    public int BrawlPassTokens;
    public int BrawlPassSeason;
    public int BrawlPassTailRewards;
    public boolean BrawlPassProgressMigrated;
    public List<String> BillingDeliveredOrderIds = new ArrayList<>();
    public List<BillingPurchase> BillingPurchases = new ArrayList<>();
    public List<String> AdminActionIds = new ArrayList<>();
    public static final class BillingPurchase {
        public String OrderId, ProductId, Description, Method, Currency, Status, DeliveryError, TelegramChargeId;
        public long BuyerAccountId, RecipientAccountId, AmountMinor, TelegramUserId;
        public int StarsAmount;
        public boolean Paid, Delivered, LegacyAmountUnknown;
        public Instant CreatedAt, PaidAt, DeliveredAt, RefundedAt;
    }
    public boolean HasPremiumPass;
    public int OldBrawlPassTokens;
    public BigInteger OldBrawlPassProgress = BigInteger.ZERO;
    public BigInteger OldPremiumPassProgress = BigInteger.ZERO;
    public boolean OldHasPremiumPass;
    public int OldBrawlPassSeason;
    public int OldBrawlPassTailRewards;
    public boolean HasArchivedBrawlPass;
    public List<Integer> UnlockedEmotes;
    public List<Integer> UnlockedPlayerThumbnails;
    public int Experience;
    public int TokenDoublers;
    public int TrophyRoadProgress;
    public Quests Quests;
    public RankedSeasonProgress RankedSeasonProgress;
    public NotificationFactory NotificationFactory;
    public transient boolean ShowWelcomePopup;
    public BattleLogEntry BattleLogs;
    public List<Integer> UnlockedSkins;
    public List<Integer> UnlockedRankedShopSkins;
    public Map<Integer, Instant> TrueSilverSkinsUnlockedAt;
    public int[] SelectedSkins;
    public Map<Integer, Integer> GlobalSelectedEmotes;
    public List<Integer> RandomSkinCharacterIds;
    public int PowerPlayGamesPlayed;
    public int ChallengeGamesWins;
    public int ChallengeGamesLosses;
    public int RoboRumbleDifficulty;
    public int RoboRumbleHighestDifficulty;
    public int RoboRumbleEventSlot;
    public Instant RoboRumbleEventEndTime = Instant.ofEpochSecond(-62135596800L);
    private Map<Integer, SpecialEventProgress> RoboRumbleProgress = new HashMap<>();
    private transient final Object RoboRumbleProgressGate = new Object();
    public int BossFightDifficulty;
    public int BossFightHighestDifficulty;
    public int BossFightEventSlot;
    public Instant BossFightEventEndTime = Instant.ofEpochSecond(-62135596800L);
    private Map<Integer, SpecialEventProgress> BossFightProgress = new HashMap<>();
    private transient final Object BossFightProgressGate = new Object();
    public int TownCrushDifficulty;
    public int TownCrushHighestDifficulty;
    public int TownCrushEventSlot;
    public Instant TownCrushEventEndTime = Instant.ofEpochSecond(-62135596800L);
    private Map<Integer, SpecialEventProgress> TownCrushProgress = new HashMap<>();
    private transient final Object TownCrushProgressGate = new Object();
    private static class SpecialEventProgress {
        public Instant EndTime;
        public int Difficulty;
    }
    public int PowerPlayScore;
    public int PowerPlayHighestScore;
    @SerializedName("SoloLeaguePoints")
    public int SoloLeagueRank;
    public int SoloHighLeagueRank;
    @SerializedName("TeamLeaguePoints")
    public int TeamLeagueRank;
    public int TeamHighLeagueRank;
    public int ProfileSoloHighLeagueRank;
    public int ProfileTeamHighLeagueRank;
    public int SoloLeagueRankPoints;
    public int TeamLeagueRankPoints;
    @SerializedName("SoloHighLeaguePoints")
    public int SoloLeagueHighPointsValue;
    @SerializedName("TeamHighLeaguePoints")
    public int TeamLeagueHighPointsValue;
    public int SoloRankedRewardsUnlocked;
    public int TeamRankedRewardsUnlocked;
    public int getSoloLeaguePoints() { return SoloLeagueRankPoints; }
    public void setSoloLeaguePoints(int value) { SoloLeagueRankPoints = value; }
    public int getSoloLeagueHighPoints() { return SoloLeagueHighPointsValue; }
    public void setSoloLeagueHighPoints(int value) { SoloLeagueHighPointsValue = value; }
    public int getTeamLeaguePoints() { return TeamLeagueRankPoints; }
    public void setTeamLeaguePoints(int value) { TeamLeagueRankPoints = value; }
    public int getTeamLeagueHighPoints() { return TeamLeagueHighPointsValue; }
    public void setTeamLeagueHighPoints(int value) { TeamLeagueHighPointsValue = value; }
    public int BattleTokens;
    public Instant BattleTokensRefreshStart;
    public Instant PremiumEndTime = Instant.ofEpochSecond(-62135596800L);
    public Instant ChatBanEndTime = Instant.ofEpochSecond(-62135596800L);
    public Instant BanEndTime = Instant.ofEpochSecond(-62135596800L);
    public int RankedDraftDodgeCount;
    public Instant RankedDraftLastDodgeTime = Instant.ofEpochSecond(-62135596800L);
    public Instant RankedDraftBanEndTime = Instant.ofEpochSecond(-62135596800L);
    public List<Long> ReportsIds;
    public boolean BlockFriendRequests;
    public String IpAddress;
    public String Device;
    public String ContentCreator;
    public List<String> OffersClaimed;
    public List<String> GrantedSpecialQuestIds;
    public transient EventData[] Events;
    public transient boolean HomeDataLoaded;
    private transient String SkinOfferBannerSignature;
    public PlayerThumbnailData getThumbnail() {
        if (DataTables.Get(DataType.PlayerThumbnail) == null) return null;
        return DataTables.Get(DataType.PlayerThumbnail).GetDataByGlobalId(ThumbnailId);
    }
    public NameColorData getNameColor() {
        if (DataTables.Get(DataType.NameColor) == null) return null;
        return DataTables.Get(DataType.NameColor).GetDataByGlobalId(NameColorId);
    }
    public CharacterData getCharacter() {
        if (DataTables.Get(DataType.Character) == null) return null;
        return DataTables.Get(DataType.Character).GetDataByGlobalId(CharacterId);
    }
    public transient HomeMode HomeMode;
    public Instant LastVisitHomeTime;
    public Instant LastRotateDate = Instant.ofEpochSecond(-62135596800L);
    public Instant LastAutoShopRefreshDate = Instant.ofEpochSecond(-62135596800L);
    public Instant LastQuestRefreshDate;
    public Instant QuestSeasonStartDate;
    public transient boolean ShouldUpdateDay;
    public boolean IsClearedNotification = false;
    public ClientHome() {
        ThumbnailId = GlobalId.CreateGlobalId(28, 0);
        NameColorId = GlobalId.CreateGlobalId(43, 0);
        CharacterId = GlobalId.CreateGlobalId(16, 0);
        SelectedSkins = new int[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        OfferBundles = new ArrayList<>();
        OffersClaimed = new ArrayList<>();
        GrantedSpecialQuestIds = new ArrayList<>();
        ReportsIds = new ArrayList<>();
        UnlockedSkins = new ArrayList<>();
        UnlockedRankedShopSkins = new ArrayList<>();
        TrueSilverSkinsUnlockedAt = new HashMap<>();
        RandomSkinCharacterIds = new ArrayList<>();
        LastVisitHomeTime = Instant.EPOCH;
        LastQuestRefreshDate = Instant.EPOCH;
        QuestSeasonStartDate = Instant.EPOCH;
        TrophyRoadProgress = 1;
        BrawlPassProgress = BigInteger.ONE;
        PremiumPassProgress = BigInteger.ONE;
        OldBrawlPassTokens = 0;
        OldBrawlPassProgress = BigInteger.ZERO;
        OldPremiumPassProgress = BigInteger.ZERO;
        OldHasPremiumPass = false;
        OldBrawlPassSeason = 0;
        SoloLeagueRank = 1;
        SoloHighLeagueRank = 1;
        TeamLeagueRank = 1;
        TeamHighLeagueRank = 1;
        ProfileSoloHighLeagueRank = 1;
        ProfileTeamHighLeagueRank = 1;
        SoloLeagueHighPointsValue = 0;
        TeamLeagueHighPointsValue = 0;
        SoloRankedRewardsUnlocked = 0;
        TeamRankedRewardsUnlocked = 0;
        UnlockedEmotes = new ArrayList<>();
        UnlockedPlayerThumbnails = new ArrayList<>(List.of(ThumbnailId));
        BattleTokens = 200;
        BattleTokensRefreshStart = MIN_INSTANT;
        RankedSeasonProgress = new RankedSeasonProgress();
        if (OffersClaimed == null) OffersClaimed = new ArrayList<>();
        if (GrantedSpecialQuestIds == null) GrantedSpecialQuestIds = new ArrayList<>();
        if (BattleLogs == null) {
            BattleLogs = new BattleLogEntry();
        } else {
            BattleLogs.Sanitize();
        }
        if (NotificationFactory == null) {
            NotificationFactory = new NotificationFactory();
        }
        if (GlobalSelectedEmotes == null) {
            GlobalSelectedEmotes = new HashMap<>();
            GlobalSelectedEmotes.put(4, 0);
            GlobalSelectedEmotes.put(5, 0);
        }
        if (TrueSilverSkinsUnlockedAt == null) {
            TrueSilverSkinsUnlockedAt = new HashMap<>();
        }
        if (UnlockedRankedShopSkins == null) UnlockedRankedShopSkins = new ArrayList<>();
        if (UnlockedPlayerThumbnails == null) UnlockedPlayerThumbnails = new ArrayList<>();
        if (!UnlockedPlayerThumbnails.contains(ThumbnailId)) {
            UnlockedPlayerThumbnails.add(ThumbnailId);
        }
        NormalizeLeagueRanks();
        EnsureRankedSeasonProgress();
    }
    public boolean IsThumbnailUnlocked(int thumbnailGlobalId) {
        if (thumbnailGlobalId == ThumbnailId) return true;
        if (DataTables.Get(DataType.PlayerThumbnail) == null) return false;
        PlayerThumbnailData thumbnailData = DataTables.Get(DataType.PlayerThumbnail).GetDataByGlobalId(thumbnailGlobalId);
        if (thumbnailData == null) return false;
        if (!thumbnailData.IsReward && !thumbnailData.HideInCatalogWhenNotOwned) return true;
        return UnlockedPlayerThumbnails != null && UnlockedPlayerThumbnails.contains(thumbnailGlobalId);
    }
    public void UnlockThumbnail(int thumbnailGlobalId) {
        if (UnlockedPlayerThumbnails == null) UnlockedPlayerThumbnails = new ArrayList<>();
        if (!UnlockedPlayerThumbnails.contains(thumbnailGlobalId)) UnlockedPlayerThumbnails.add(thumbnailGlobalId);
    }
    public boolean IsRankedShopSkinUnlocked(int skinGlobalId) {
        if (!RankedSeasonProgress.GetShopUnlockSkinGlobalIds().contains(skinGlobalId)) return true;
        return UnlockedRankedShopSkins != null && UnlockedRankedShopSkins.contains(skinGlobalId);
    }
    public void UnlockRankedShopSkin(int skinGlobalId) {
        if (UnlockedRankedShopSkins == null) UnlockedRankedShopSkins = new ArrayList<>();
        if (!UnlockedRankedShopSkins.contains(skinGlobalId)) {
            UnlockedRankedShopSkins.add(skinGlobalId);
            RefreshShopContentForRankedUnlock();
        }
    }
    public boolean IsRandomSkinEnabled(int characterGlobalId) {
        return characterGlobalId > 0 && RandomSkinCharacterIds != null && RandomSkinCharacterIds.contains(characterGlobalId);
    }
    public void SetRandomSkinEnabled(int characterGlobalId, boolean enabled) {
        if (characterGlobalId <= 0) return;
        if (RandomSkinCharacterIds == null) RandomSkinCharacterIds = new ArrayList<>();
        if (enabled) {
            if (!RandomSkinCharacterIds.contains(characterGlobalId)) RandomSkinCharacterIds.add(characterGlobalId);
        } else {
            RandomSkinCharacterIds.remove((Integer) characterGlobalId);
        }
    }
    public List<Integer> GetOwnedSkinsForCharacter(int characterGlobalId) {
        List<Integer> result = new ArrayList<>();
        if (characterGlobalId <= 0) return result;
        if (DataTables.Get(DataType.Character) == null) return result;
        CharacterData character = DataTables.Get(DataType.Character).GetDataByGlobalId(characterGlobalId);
        if (character == null) return result;
        DataTable skinTable = DataTables.Get(DataType.Skin);
        if (skinTable == null) return result;
        SkinData defaultSkin = null;
        if (character.DefaultSkin != null && !character.DefaultSkin.isBlank()) defaultSkin = skinTable.GetData(character.DefaultSkin);
        for (LogicData data : skinTable.GetDatas()) {
            if (!(data instanceof SkinData skin)) continue;
            if (skin.Disabled) continue;
            SkinConfData conf = skin.GetConf();
            if (conf == null || conf.Character == null || conf.Character.isBlank()) continue;
            if (!conf.Character.equalsIgnoreCase(character.Name)) continue;
            int skinGlobalId = skin.GetGlobalId();
            boolean isDefault = defaultSkin != null && skinGlobalId == defaultSkin.GetGlobalId();
            if (!isDefault && (UnlockedSkins == null || !UnlockedSkins.contains(skinGlobalId))) continue;
            result.add(skinGlobalId);
        }
        return result;
    }
    public int RollRandomSkinForCharacter(int characterGlobalId) {
        List<Integer> owned = GetOwnedSkinsForCharacter(characterGlobalId);
        if (owned.isEmpty()) return 0;
        return owned.get(SHARED_RANDOM.nextInt(owned.size()));
    }
    public int ResolveBattleSkinId(int characterGlobalId) {
        if (characterGlobalId <= 0) return 0;
        if (IsRandomSkinEnabled(characterGlobalId)) {
            int randomSkin = RollRandomSkinForCharacter(characterGlobalId);
            if (randomSkin > 0) return randomSkin;
        }
        if (SelectedSkins == null) return 0;
        int skinIndex = GlobalId.GetInstanceId(characterGlobalId);
        if (skinIndex < 0 || skinIndex >= SelectedSkins.length) return 0;
        int instanceId = SelectedSkins[skinIndex];
        if (instanceId <= 0) return 0;
        return GlobalId.CreateGlobalId(29, instanceId);
    }
    public void EnsureSelectedSkinsCapacity(int characterInstanceId) {
        if (characterInstanceId < 0) return;
        if (SelectedSkins == null) SelectedSkins = new int[0];
        if (characterInstanceId >= SelectedSkins.length) SelectedSkins = Arrays.copyOf(SelectedSkins, characterInstanceId + 1);
    }
    public void ResetRankedDraftDodgesIfExpired(Instant utcNow) {
        if (RankedDraftLastDodgeTime == null || RankedDraftLastDodgeTime.equals(MIN_INSTANT) || RankedDraftLastDodgeTime.equals(Instant.EPOCH)) return;
        if (Duration.between(RankedDraftLastDodgeTime, utcNow).toHours() < 10) return;
        RankedDraftDodgeCount = 0;
        RankedDraftLastDodgeTime = Instant.EPOCH;
        RankedDraftBanEndTime = Instant.EPOCH;
    }
    public int GetRankedDraftCooldownRemainingSeconds(Instant utcNow) {
        ResetRankedDraftDodgesIfExpired(utcNow);
        if (RankedDraftBanEndTime == null || !RankedDraftBanEndTime.isAfter(utcNow)) return 0;
        return Math.max(0, (int) Math.ceil((double) Duration.between(utcNow, RankedDraftBanEndTime).getSeconds()));
    }
    public int RegisterRankedDraftDodge(Instant utcNow) {
        ResetRankedDraftDodgesIfExpired(utcNow);
        RankedDraftDodgeCount++;
        RankedDraftLastDodgeTime = utcNow;
        int cooldownSeconds = GetRankedDraftCooldownSeconds(RankedDraftDodgeCount);
        RankedDraftBanEndTime = cooldownSeconds > 0 ? utcNow.plusSeconds(cooldownSeconds) : Instant.EPOCH;
        return cooldownSeconds;
    }
    private static int GetRankedDraftCooldownSeconds(int dodgeCount) {
        if (dodgeCount <= 1) return 0;
        if (dodgeCount == 2) return 5 * 60;
        if (dodgeCount == 3) return 15 * 60;
        if (dodgeCount == 4) return 30 * 60;
        if (dodgeCount == 5) return 60 * 60;
        return 24 * 60 * 60;
    }
    public void RefreshShopContentForRankedUnlock() {
        if (HomeMode == null) return;
        if (OfferBundles == null) OfferBundles = new ArrayList<>();
        RotateShopContent(Instant.now(), OfferBundles.isEmpty());
    }
    public void RefreshShopContentForHeroUnlock() {
        RefreshShopContentForRankedUnlock();
    }
    private void NormalizeLeagueRanks() {
        if (SoloHighLeagueRank <= 0 && SoloLeagueHighPointsValue > 0 && SoloLeagueHighPointsValue <= 19) {
            SoloHighLeagueRank = Math.max(SoloLeagueRank, SoloLeagueHighPointsValue);
            SoloLeagueHighPointsValue = SoloLeagueRank == SoloHighLeagueRank ? SoloLeagueRankPoints : 0;
        }
        if (TeamHighLeagueRank <= 0 && TeamLeagueHighPointsValue > 0 && TeamLeagueHighPointsValue <= 19) {
            TeamHighLeagueRank = Math.max(TeamLeagueRank, TeamLeagueHighPointsValue);
            TeamLeagueHighPointsValue = TeamLeagueRank == TeamHighLeagueRank ? TeamLeagueRankPoints : 0;
        }
        if (SoloLeagueRank <= 0) SoloLeagueRank = 1;
        if (SoloHighLeagueRank <= 0) SoloHighLeagueRank = SoloLeagueRank;
        if (ProfileSoloHighLeagueRank <= 0) ProfileSoloHighLeagueRank = Math.max(SoloLeagueRank, SoloHighLeagueRank);
        if (TeamLeagueRank <= 0) TeamLeagueRank = 1;
        if (TeamHighLeagueRank <= 0) TeamHighLeagueRank = TeamLeagueRank;
        if (ProfileTeamHighLeagueRank <= 0) ProfileTeamHighLeagueRank = Math.max(TeamLeagueRank, TeamHighLeagueRank);
        if (SoloLeagueHighPointsValue < 0) SoloLeagueHighPointsValue = 0;
        if (TeamLeagueHighPointsValue < 0) TeamLeagueHighPointsValue = 0;
        SoloLeagueRankPoints = clamp(SoloLeagueRankPoints, 0, RANKED_POINTS_PER_RANK);
        TeamLeagueRankPoints = clamp(TeamLeagueRankPoints, 0, RANKED_POINTS_PER_RANK);
        SoloLeagueHighPointsValue = clamp(SoloLeagueHighPointsValue, 0, RANKED_POINTS_PER_RANK);
        TeamLeagueHighPointsValue = clamp(TeamLeagueHighPointsValue, 0, RANKED_POINTS_PER_RANK);
    }
    private static int clamp(int v, int min, int max) {
        return Math.min(Math.max(v, min), max);
    }
    public RankedSeasonProgress EnsureRankedSeasonProgress() {
        if (RankedSeasonProgress == null) RankedSeasonProgress = new RankedSeasonProgress();
        return RankedSeasonProgress;
    }
    public void UnlockRankedRewardsForMatchType(int matchType) {
        if (matchType == 1) TeamRankedRewardsUnlocked = 1;
        else SoloRankedRewardsUnlocked = 1;
    }
    public int GetHighestRankedLeagueRank() {
        return Math.max(Math.max(SoloLeagueRank, SoloHighLeagueRank), Math.max(TeamLeagueRank, TeamHighLeagueRank));
    }
    public void HomeVisited() {
        RotateShopContent(Instant.now(), OfferBundles == null || OfferBundles.isEmpty());
        LastVisitHomeTime = Instant.now();
        if (Quests == null && TrophyRoadProgress >= 11) {
            EnsureQuestsForCurrentSeason(Instant.now());
        }
        boolean hasDonation = false;
        if (NotificationFactory != null && NotificationFactory.NotificationList != null) {
            for (Notification n : NotificationFactory.NotificationList) {
                if (n != null && n.DonationGlobalId == 59) { hasDonation = true; break; }
            }
        }
        if (!IsClearedNotification || hasDonation) {
            NotificationFactory.ClearAllNotif();
            IsClearedNotification = true;
        }
    }
    public void ArchiveBrawlPassProgress() {
        ArchiveBrawlPassProgress(GetCurrentBrawlPassSeason());
    }
    public synchronized void ArchiveBrawlPassProgress(int season) {
        OldBrawlPassTokens = BrawlPassTokens;
        OldBrawlPassProgress = BrawlPassProgress != null ? BrawlPassProgress : BigInteger.ZERO;
        OldPremiumPassProgress = PremiumPassProgress != null ? PremiumPassProgress : BigInteger.ZERO;
        OldHasPremiumPass = HasPremiumPass;
        OldBrawlPassTailRewards = BrawlPassTailRewards;
        OldBrawlPassSeason = season;
        HasArchivedBrawlPass = true;
    }
    public int GetCurrentBrawlPassSeason() {
        EnsureCurrentBrawlPassSeason();
        return BrawlPassSeason;
    }
    public synchronized boolean EnsureCurrentBrawlPassSeason() {
        boolean changed = NormalizeLegacyBrawlPassSeasons();
        int currentSeason = BrawlPassSeasonConfig.SeasonNumber();
        if (BrawlPassSeason <= 0) {
            BrawlPassSeason = currentSeason;
            changed = true;
        }
        changed |= RepairLegacyBrawlPassProgress(BrawlPassSeason);
        if (BrawlPassSeason < currentSeason) {
            changed |= ResetBrawlPassProgress(BrawlPassSeason, currentSeason);
        }
        return changed;
    }
    private boolean RepairLegacyBrawlPassProgress(int season) {
        if (BrawlPassProgressMigrated || !DataTables.IsLoaded()) return false;
        BrawlPassTokens = Math.max(BrawlPassTokens, GetClaimedBrawlPassTokenFloor(season, BrawlPassProgress, PremiumPassProgress));
        if (HasOldBrawlPass()) {
            int oldSeason = HasArchivedBrawlPass || OldBrawlPassSeason != 0 ? OldBrawlPassSeason : Math.max(0, season - 1);
            OldBrawlPassTokens = Math.max(OldBrawlPassTokens, GetClaimedBrawlPassTokenFloor(oldSeason, OldBrawlPassProgress, OldPremiumPassProgress));
        }
        BrawlPassTailRewards = Math.max(0, BrawlPassTailRewards);
        OldBrawlPassTailRewards = Math.max(0, OldBrawlPassTailRewards);
        BrawlPassProgressMigrated = true;
        return true;
    }
    private static int GetClaimedBrawlPassTokenFloor(int season, BigInteger freeProgress, BigInteger premiumProgress) {
        int floor = 0;
        for (LogicData data : DataTables.Get(DataType.Milestone).GetDatas()) {
            if (!(data instanceof MilestoneData milestone) || milestone.Season != season || milestone.Index < 0 || milestone.Index > 125) continue;
            BigInteger claimed = milestone.Type == 10 ? freeProgress : milestone.Type == 9 ? premiumProgress : null;
            if (claimed != null && claimed.signum() > 0 && claimed.testBit(milestone.Index + 2)) {
                floor = Math.max(floor, milestone.ProgressStart + milestone.Progress);
            }
        }
        return floor;
    }
    public static List<MilestoneData> GetBrawlPassMilestones(int track, int season) {
        List<MilestoneData> milestones = new ArrayList<>();
        for (LogicData data : DataTables.Get(DataType.Milestone).GetDatas()) {
            if (data instanceof MilestoneData milestone && milestone.Type == track && milestone.Season == season) milestones.add(milestone);
        }
        milestones.sort(java.util.Comparator.comparingInt(milestone -> milestone.Index));
        return milestones;
    }
    public synchronized void AddBrawlPassTokens(int count) {
        EnsureCurrentBrawlPassSeason();
        BrawlPassTokens = (int) Math.min(Integer.MAX_VALUE, Math.max(0L, BrawlPassTokens) + Math.max(0L, count));
    }
    public int GetBrawlPassProgressAfterLevels(int levels) {
        int season = GetCurrentBrawlPassSeason();
        int tokens = BrawlPassTokens;
        TreeSet<Integer> thresholds = new TreeSet<>();
        for (MilestoneData milestone : GetBrawlPassMilestones(10, season)) thresholds.add(milestone.ProgressStart + milestone.Progress);
        for (int i = 0; i < levels; i++) {
            Integer next = thresholds.higher(tokens);
            if (next == null) break;
            tokens = next;
        }
        return tokens;
    }
    public boolean NormalizeLegacyBrawlPassSeasons() {
        int currentSeason = BrawlPassSeasonConfig.SeasonNumber();
        if (BrawlPassSeason != 0 || HasArchivedBrawlPass || OldBrawlPassSeason != currentSeason || !HasOldBrawlPassProgress()) return false;
        BrawlPassSeason = currentSeason;
        OldBrawlPassSeason = Math.max(0, currentSeason - 1);
        HasArchivedBrawlPass = true;
        return true;
    }
    public boolean ResetBrawlPassProgress() {
        int currentSeason = BrawlPassSeasonConfig.SeasonNumber();
        if (NormalizeLegacyBrawlPassSeasons()) return true;
        if (BrawlPassSeason == currentSeason) return false;
        return ResetBrawlPassProgress(BrawlPassSeason > 0 ? BrawlPassSeason : Math.max(0, currentSeason - 1));
    }
    public boolean ResetBrawlPassProgress(int season) {
        return ResetBrawlPassProgress(season, BrawlPassSeasonConfig.SeasonNumber());
    }
    public synchronized boolean ResetBrawlPassProgress(int season, int currentSeason) {
        if (season < 0 || season >= currentSeason) throw new IllegalArgumentException("Archived season must be older than configured Brawl Pass season");
        boolean repaired = NormalizeLegacyBrawlPassSeasons();
        if (BrawlPassSeason == currentSeason) return repaired;
        if (BrawlPassSeason == 0 && HasOldBrawlPass() && GetEffectiveOldBrawlPassSeason() == season) return false;
        if (BrawlPassSeason > 0 && BrawlPassSeason != season) throw new IllegalArgumentException("Brawl Pass season does not match the account progress");
        RepairLegacyBrawlPassProgress(season);
        ArchiveBrawlPassProgress(season);
        BrawlPassTokens = 0;
        BrawlPassProgress = BigInteger.ZERO;
        PremiumPassProgress = BigInteger.ZERO;
        HasPremiumPass = false;
        BrawlPassTailRewards = 0;
        BrawlPassSeason = currentSeason;
        return true;
    }
    public boolean HasOldBrawlPass() {
        return HasArchivedBrawlPass || HasOldBrawlPassProgress();
    }
    private boolean HasOldBrawlPassProgress() {
        return OldBrawlPassTokens > 0 || OldBrawlPassTailRewards > 0 || OldHasPremiumPass
            || (OldBrawlPassProgress != null && OldBrawlPassProgress.signum() != 0)
            || (OldPremiumPassProgress != null && OldPremiumPassProgress.signum() != 0);
    }
    public int GetEffectiveOldBrawlPassSeason() {
        EnsureCurrentBrawlPassSeason();
        if (!HasOldBrawlPass()) return 0;
        if (HasArchivedBrawlPass || OldBrawlPassSeason != 0) {
            return OldBrawlPassSeason;
        }
        return HasOldBrawlPass() ? Math.max(0, GetCurrentBrawlPassSeason() - 1) : 0;
    }
    private void EncodeBrawlPassSeasons(ByteStream encoder) {
        int currentSeason = GetCurrentBrawlPassSeason();
        int oldSeason = GetEffectiveOldBrawlPassSeason();
        boolean hasArchive = HasOldBrawlPass() && oldSeason >= 0 && oldSeason < currentSeason;
        encoder.WriteVInt(hasArchive ? 2 : 1);
        EncodeBrawlPassSeason(encoder, currentSeason, BrawlPassTokens, HasPremiumPass, BrawlPassTailRewards, PremiumPassProgress, BrawlPassProgress);
        if (hasArchive) EncodeBrawlPassSeason(encoder, oldSeason, OldBrawlPassTokens, OldHasPremiumPass, OldBrawlPassTailRewards, OldPremiumPassProgress, OldBrawlPassProgress);
    }
    private static void EncodeBrawlPassSeason(ByteStream encoder, int season, int tokens, boolean premium, int tailRewards, BigInteger premiumProgress, BigInteger freeProgress) {
        encoder.WriteVInt(season);
        encoder.WriteVInt(Math.max(0, tokens));
        encoder.WriteBoolean(premium);
        encoder.WriteVInt(Math.max(0, tailRewards));
        encoder.WriteBoolean(false);
        encoder.WriteBoolean(true);
        encoder.WriteLongLong128(premiumProgress != null ? premiumProgress : BigInteger.ZERO);
        encoder.WriteBoolean(true);
        encoder.WriteLongLong128(freeProgress != null ? freeProgress : BigInteger.ZERO);
    }
    public void ClearAllQuests(Instant time) {
        ClearAllQuests(time, null);
    }
    public void ClearAllQuests(Instant time, List<Hero> unlockedHeroes) {
        if (Quests == null) Quests = new Quests();
        if (Quests.QuestList == null) Quests.QuestList = new ArrayList<>();
        synchronized (Quests.getQuestListLock()) {
            Quests.QuestList.clear();
        }
        if (GrantedSpecialQuestIds == null) GrantedSpecialQuestIds = new ArrayList<>();
        GrantedSpecialQuestIds.clear();
        if (TrophyRoadProgress < 11) {
            LastQuestRefreshDate = Instant.EPOCH;
            QuestSeasonStartDate = Instant.EPOCH;
            return;
        }
        LastQuestRefreshDate = Instant.EPOCH;
        QuestSeasonStartDate = Instant.EPOCH;
        EnsureQuestsForCurrentSeason(time, unlockedHeroes, false);
    }
    public void EnsureQuestsForCurrentSeason(Instant time) {
        EnsureQuestsForCurrentSeason(time, null, true);
    }
    public void EnsureQuestsForCurrentSeason(Instant time, List<Hero> unlockedHeroes) {
        EnsureQuestsForCurrentSeason(time, unlockedHeroes, true);
    }
    public void EnsureQuestsForCurrentSeason(Instant time, List<Hero> unlockedHeroes, boolean includeMissedRegularQuests) {
        if (TrophyRoadProgress < 11) return;
        Instant seasonStartUtc = GetBrawlPassSeasonStartUtc(time);
        boolean needsInitialization = Quests == null || (QuestSeasonStartDate != null && QuestSeasonStartDate.isBefore(seasonStartUtc));
        if (Quests == null && QuestSeasonStartDate == null) needsInitialization = true;
        if (!needsInitialization) return;
        if (Quests != null && QuestSeasonStartDate != null && QuestSeasonStartDate.isBefore(seasonStartUtc) && LastQuestRefreshDate != null && !truncateToDay(LastQuestRefreshDate).isBefore(truncateToDay(seasonStartUtc))) {
            QuestSeasonStartDate = seasonStartUtc;
            if (Quests.QuestList == null) Quests.QuestList = new ArrayList<>();
            return;
        }
        if (Quests == null) Quests = new Quests();
        if (Quests.QuestList == null) Quests.QuestList = new ArrayList<>();
        if (unlockedHeroes == null) {
            if (HomeMode != null && HomeMode.Avatar != null && HomeMode.Avatar.Heroes != null) unlockedHeroes = HomeMode.Avatar.Heroes;
            else unlockedHeroes = new ArrayList<>();
        }
        List<Hero> heroesForQuests = unlockedHeroes;
        synchronized (Quests.getQuestListLock()) {
            List<Quest> preservedSpecialQuests = new ArrayList<>();
            for (Quest quest : Quests.QuestList) {
                if (quest != null && quest.IsManualSpecialQuest && quest.ManualSpecialQuestId != null && !quest.ManualSpecialQuestId.isBlank()
                    && (quest.ManualSpecialQuestEndTimeUtc == null || quest.ManualSpecialQuestEndTimeUtc.isAfter(time))
                    && (quest.CharacterId == 0 || hasHeroWithId(heroesForQuests, quest.CharacterId))) {
                    preservedSpecialQuests.add(quest.Clone());
                }
            }
            Quests.QuestList.clear();
            Quests.AddDailyQuests(heroesForQuests);
            Quests.AddNonDailyQuests(heroesForQuests);
            int missedRegularRefreshes = includeMissedRegularQuests ? CountRegularQuestRefreshesSinceSeasonStart(seasonStartUtc, time) : 0;
            for (int i = 0; i < missedRegularRefreshes; i++) {
                Quests.AddNonDailyQuests(heroesForQuests);
            }
            for (Quest quest : preservedSpecialQuests) {
                Quests.QuestList.add(quest);
            }
        }
        LastQuestRefreshDate = truncateToDay(time);
        QuestSeasonStartDate = seasonStartUtc;
    }
    private static boolean hasHeroWithId(List<Hero> heroes, int characterId) {
        if (heroes == null) return false;
        for (Hero hero : heroes) {
            if (hero != null && hero.CharacterId == characterId) return true;
        }
        return false;
    }
    public void Tick() {
        EnsureCurrentBrawlPassSeason();
        LastVisitHomeTime = Instant.now();
        while (ShouldAddTokens()) {
            BattleTokensRefreshStart = BattleTokensRefreshStart.plus(Duration.ofMinutes(30));
            BattleTokens = Math.min(200, BattleTokens + 30);
            if (BattleTokens == 200) {
                BattleTokensRefreshStart = MIN_INSTANT;
                break;
            }
        }
        RotateShopContent(Instant.now(), OfferBundles == null || OfferBundles.isEmpty());
    }
    public int GetbattleTokensRefreshSeconds() {
        if (BattleTokensRefreshStart == null || BattleTokensRefreshStart.equals(MIN_INSTANT)) return -1;
        return (int) Duration.between(Instant.now(), BattleTokensRefreshStart.plus(Duration.ofMinutes(30))).getSeconds();
    }
    public boolean ShouldAddTokens() {
        if (BattleTokensRefreshStart == null || BattleTokensRefreshStart.equals(MIN_INSTANT)) return false;
        return GetbattleTokensRefreshSeconds() < 1;
    }
    public int ConsumeBattleTokens(int requested) {
        if (requested <= 0) return 0;
        int granted = Math.min(requested, BattleTokens);
        BattleTokens -= granted;
        if (BattleTokens < 200 && (BattleTokensRefreshStart == null || BattleTokensRefreshStart.equals(MIN_INSTANT))) {
            BattleTokensRefreshStart = Instant.now();
        }
        return granted;
    }
    public void PurchaseOffer(int index) {
        PurchaseOffer(index, new boolean[1]);
    }
    public void PurchaseOffer(int index, boolean[] testItemGrantedOut) {
        testItemGrantedOut[0] = false;
        if (index < 0 || OfferBundles == null || index >= OfferBundles.size()) {
            System.out.println("[Shop] PurchaseOffer REJECT bad index " + index + " (have " + (OfferBundles == null ? 0 : OfferBundles.size()) + ")");
            return;
        }
        OfferBundle bundle = OfferBundles.get(index);
        Instant purchaseTime = Instant.now();
        if (bundle == null || bundle.Cost < 0 || (bundle.Currency != 0 && bundle.Currency != 1 && bundle.Currency != 3)
            || bundle.EndTime != null && !bundle.EndTime.isAfter(purchaseTime)
            || bundle.StartTime != null && bundle.StartTime.isAfter(purchaseTime)
            || bundle.Items == null || bundle.Items.isEmpty()) {
            System.out.println("[Shop] PurchaseOffer REJECT invalid or expired offer idx=" + index);
            return;
        }
        if (bundle.Purchased) {
            System.out.println("[Shop] PurchaseOffer REJECT already purchased idx=" + index + " claim=" + bundle.Claim);
            return;
        }
        if (bundle.Claim != null && !bundle.Claim.isBlank() && OffersClaimed != null && OffersClaimed.contains(bundle.Claim)) {
            System.out.println("[Shop] PurchaseOffer REJECT already claimed idx=" + index + " claim=" + bundle.Claim);
            return;
        }
        if (bundle.IsBillingOffer()) {
            System.out.println("[Shop] PurchaseOffer REJECT billing-only idx=" + index + " claim=" + bundle.Claim);
            return;
        }
        Set<Integer> reservedThumbnails = new HashSet<>();
        for (Offer item : bundle.Items) {
            if (item != null && item.Type == ShopItem.PlayerThumbnail) {
                PlayerThumbnailData thumbnail = GlobalId.GetClassId(item.ItemDataId) == 28
                    ? DataTables.Get(DataType.PlayerThumbnail).GetDataByGlobalId(item.ItemDataId) : null;
                if (item.Count != 1 || thumbnail == null || IsThumbnailUnlocked(item.ItemDataId)
                    || !reservedThumbnails.add(item.ItemDataId)) {
                    System.out.println("[Shop] PurchaseOffer REJECT unavailable thumbnail idx=" + index);
                    return;
                }
            }
            if (item == null || item.Type != ShopItem.GuaranteedHero) continue;
            CharacterData character = GlobalId.GetClassId(item.ItemDataId) == 16
                ? DataTables.Get(DataType.Character).GetDataByGlobalId(item.ItemDataId) : null;
            CardData unlock = character == null ? null : DataTables.GetUnlockCardFor(character);
            if (item.Count != 1 || character == null || !character.IsHero() || character.Disabled || character.LockedForChronos
                || unlock == null || unlock.Disabled || unlock.LockedForChronos || HomeMode.Avatar.HasHero(item.ItemDataId)) {
                System.out.println("[Shop] PurchaseOffer REJECT unavailable hero idx=" + index);
                return;
            }
        }
        Map<Offer, DeliveryUnit> preparedPinPacks = new HashMap<>();
        boolean hasTestItem = false;
        if (bundle.Items != null) {
            for (Offer o : bundle.Items) {
                if (o != null && o.IsTestItem) { hasTestItem = true; break; }
            }
        }
        if (hasTestItem && (ShouldSkipJsonOfferBundle(bundle, Instant.now()) || bundle.Cost < 0 || (bundle.Currency != 0 && bundle.Currency != 1 && bundle.Currency != 3))) {
            return;
        }
        Set<Integer> reservedPins = new HashSet<>();
        if (bundle.Items != null) {
            for (Offer offer : bundle.Items) {
                if (offer == null) continue;
                if (offer.Type != ShopItem.RandomEmotes && offer.Type != ShopItem.EmoteBundle) continue;
                DeliveryUnit unit = new DeliveryUnit(100);
                if (!TryAddPinPackDrops(unit, reservedPins, null)) {
                    System.out.println("[Shop] PurchaseOffer REJECT unavailable pin pack idx=" + index + " claim=" + bundle.Claim);
                    return;
                }
                preparedPinPacks.put(offer, unit);
                for (GatchaDrop drop : unit.GetDrops()) reservedPins.add(drop.PinGlobalId);
            }
        }
        if (bundle.Currency == 0) {
            if (!HomeMode.Avatar.UseDiamonds(bundle.Cost)) {
                System.out.println("[Shop] PurchaseOffer REJECT no diamonds idx=" + index + " cost=" + bundle.Cost);
                return;
            }
        } else if (bundle.Currency == 1) {
            if (!HomeMode.Avatar.UseGold(bundle.Cost)) {
                System.out.println("[Shop] PurchaseOffer REJECT no gold idx=" + index + " cost=" + bundle.Cost);
                return;
            }
        } else if (bundle.Currency == 3) {
            if (!HomeMode.Avatar.UseStarPoints(bundle.Cost)) {
                System.out.println("[Shop] PurchaseOffer REJECT no starpoints idx=" + index + " cost=" + bundle.Cost);
                return;
            }
        }
        System.out.println("[Shop] PurchaseOffer OK idx=" + index + " claim=" + bundle.Claim + " currency=" + bundle.Currency + " cost=" + bundle.Cost);
        if ("debug".equals(bundle.Claim)) {
        } else {
            if (OffersClaimed == null) OffersClaimed = new ArrayList<>();
            OffersClaimed.add(bundle.Claim);
        }
        bundle.Purchased = true;
        if (bundle.IsBillingOffer()) {
            bundle.Cost = 0;
            bundle.Currency = 0;
            bundle.isDonateOffer = false;
        }
        LogicGiveDeliveryItemsCommand command = new LogicGiveDeliveryItemsCommand();
        Random rand = new Random();
        if (bundle.Items != null) {
            for (Offer offer : bundle.Items) {
                if (offer == null) continue;
                if (offer.IsTestItem) continue;
                if (offer.Type == ShopItem.FreeBox) {
                    for (int x = 0; x < offer.Count; x++) {
                        DeliveryUnit unit = new DeliveryUnit(10);
                        HomeMode.SimulateGatcha(unit);
                        if (x + 1 != offer.Count) command.Execute(HomeMode);
                        command.DeliveryUnits.add(unit);
                    }
                }
                if (offer.Type == ShopItem.BrawlBox) {
                    for (int x = 0; x < offer.Count; x++) {
                        DeliveryUnit unit = new DeliveryUnit(100);
                        HomeMode.SimulateSkinBox(unit);
                        if (x + 1 != offer.Count) command.Execute(HomeMode);
                        command.DeliveryUnits.add(unit);
                    }
                } else if (offer.Type == ShopItem.HeroPower || offer.Type == ShopItem.WildcardPower) {
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(6);
                    reward.DataGlobalId = offer.ItemDataId;
                    reward.Count = offer.Count;
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.BigBox) {
                    for (int x = 0; x < offer.Count; x++) {
                        DeliveryUnit unit = new DeliveryUnit(12);
                        HomeMode.SimulateGatcha(unit);
                        if (x + 1 != offer.Count) command.Execute(HomeMode);
                        command.DeliveryUnits.add(unit);
                    }
                } else if (offer.Type == ShopItem.MegaBox) {
                    for (int x = 0; x < offer.Count; x++) {
                        DeliveryUnit unit = new DeliveryUnit(11);
                        HomeMode.SimulateGatcha(unit);
                        if (x + 1 != offer.Count) command.Execute(HomeMode);
                        command.DeliveryUnits.add(unit);
                    }
                } else if (offer.Type == ShopItem.Skin) {
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(9);
                    reward.SkinGlobalId = GlobalId.CreateGlobalId(29, offer.SkinDataId);
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.Gems) {
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(8);
                    reward.Count = offer.Count;
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.Coin) {
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(7);
                    reward.Count = offer.Count;
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.CoinDoubler) {
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(2);
                    reward.Count = offer.Count;
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.GuaranteedHero) {
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(1);
                    reward.DataGlobalId = offer.ItemDataId;
                    reward.Count = 1;
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.PlayerThumbnail) {
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(5);
                    reward.DataGlobalId = offer.ItemDataId;
                    reward.Count = 1;
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.Emote) {
                    if (HomeMode.Home.UnlockedEmotes == null) HomeMode.Home.UnlockedEmotes = new ArrayList<>();
                    EmoteData[] emoteDataOut = new EmoteData[1];
                    int[] emoteGlobalIdOut = new int[1];
                    if (!TryResolveOfferEmote(offer, emoteDataOut, emoteGlobalIdOut)) continue;
                    EmoteData emoteData = emoteDataOut[0];
                    int emoteGlobalId = emoteGlobalIdOut[0];
                    if (HomeMode.Home.UnlockedEmotes.contains(emoteGlobalId)) continue;
                    if (emoteData.Character != null && !emoteData.Character.isEmpty()) {
                        CharacterData characterData = DataTables.Get(DataType.Character).GetData(emoteData.Character);
                        if (characterData != null && !HomeMode.Avatar.HasHero(characterData.GetGlobalId())) continue;
                    }
                    DeliveryUnit unit = new DeliveryUnit(100);
                    GatchaDrop reward = new GatchaDrop(11);
                    reward.PinGlobalId = emoteGlobalId;
                    reward.Count = 1;
                    unit.AddDrop(reward);
                    command.DeliveryUnits.add(unit);
                } else if (offer.Type == ShopItem.RandomEmotes || offer.Type == ShopItem.EmoteBundle) {
                    command.DeliveryUnits.add(preparedPinPacks.get(offer));
                } else if (offer.Type == ShopItem.RandomEmotesPackOfRarity) {
                    int rarity = offer.SkinDataId;
                    if (rarity < 0 || rarity > 2) rarity = 0;
                    int pinsToGive = offer.Count > 0 ? offer.Count : 3;
                    DeliveryUnit unit = new DeliveryUnit(100);
                    if (TryAddPinPackDropsOfRarity(unit, rarity, pinsToGive)) {
                        command.DeliveryUnits.add(unit);
                    }
                }
                command.Execute(HomeMode);
            }
        }
        if (hasTestItem) {
            GrantTestItem();
            testItemGrantedOut[0] = true;
            return;
        }
        AvailableServerCommandMessage message = new AvailableServerCommandMessage();
        message.Command = command;
        HomeMode.GameListener.SendMessage(message);
    }
    public void GrantTestItem() {
        GrantTestItem(HomeMode.Avatar);
    }
    public void GrantTestItem(ClientAvatar avatar) {
        if (avatar == null) throw new IllegalArgumentException("Avatar is required");
        if (avatar.Heroes == null) avatar.Heroes = new ArrayList<>();
        avatar.RemoveDuplicateHeroesPreserveProgress();
        Set<String> heroNames = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        for (LogicData d : DataTables.Get(DataType.Character).GetDatas()) {
            if (!(d instanceof CharacterData character)) continue;
            if (!character.IsHero() || character.Disabled || character.LockedForChronos) continue;
            CardData unlock = DataTables.GetUnlockCardFor(character);
            if (unlock == null || unlock.Disabled || unlock.LockedForChronos) continue;
            if (!avatar.HasHero(character.GetGlobalId())) avatar.UnlockHero(character.GetGlobalId(), unlock.GetGlobalId());
            Hero hero = avatar.GetHero(character.GetGlobalId());
            hero.CardId = unlock.GetGlobalId();
            hero.Trophies = 1250;
            hero.HighestTrophies = Math.max(hero.HighestTrophies, hero.Trophies);
            hero.PowerLevel = 8;
            hero.PowerPoints = 1410;
            EnsureSelectedSkinsCapacity(character.GetInstanceId());
            heroNames.add(character.Name);
        }
        if (avatar.Starpowers == null) avatar.Starpowers = new ArrayList<>();
        Set<Integer> powers = new HashSet<>(avatar.Starpowers);
        for (LogicData d : DataTables.Get(DataType.Card).GetDatas()) {
            if (!(d instanceof CardData card)) continue;
            if (card.Disabled || card.LockedForChronos || card.Target == null || card.Target.isEmpty()) continue;
            boolean contains = false;
            for (String n : heroNames) {
                if (n.equalsIgnoreCase(card.Target)) { contains = true; break; }
            }
            if (!contains) continue;
            if (card.MetaType != 4 && (card.MetaType != 5 || !"accessory".equalsIgnoreCase(card.Type))) continue;
            if (powers.add(card.GetGlobalId())) avatar.Starpowers.add(card.GetGlobalId());
        }
        for (Hero hero : avatar.Heroes) {
            if (hero == null) continue;
            CharacterData character = hero.getCharacterData();
            if (character == null) continue;
            boolean inSet = false;
            for (String n : heroNames) {
                if (n.equalsIgnoreCase(character.Name)) { inSet = true; break; }
            }
            if (!inSet) continue;
            HeroLoadoutSelection.Resolve(avatar, character, false, true);
            HeroLoadoutSelection.Resolve(avatar, character, true, true);
        }
        if (UnlockedSkins == null) UnlockedSkins = new ArrayList<>();
        if (TrueSilverSkinsUnlockedAt == null) TrueSilverSkinsUnlockedAt = new HashMap<>();
        Set<Integer> skins = new HashSet<>(UnlockedSkins);
        for (LogicData d : DataTables.Get(DataType.Skin).GetDatas()) {
            if (!(d instanceof SkinData skin)) continue;
            if (skin.Disabled) continue;
            SkinConfData conf = skin.GetConf();
            if (conf == null || conf.Character == null || conf.Character.isEmpty()) continue;
            boolean contains = false;
            for (String n : heroNames) {
                if (n.equalsIgnoreCase(conf.Character)) { contains = true; break; }
            }
            if (!contains) continue;
            int skinId = skin.GetGlobalId();
            if (skins.add(skinId)) UnlockedSkins.add(skinId);
            if (skin.CostCoins == 10000 && !TrueSilverSkinsUnlockedAt.containsKey(skinId)) TrueSilverSkinsUnlockedAt.put(skinId, Instant.now());
        }
        avatar.HighestTrophies = Math.max(avatar.HighestTrophies, avatar.GetTrophies());
        TrophyRoadProgress = 200;
        TestItemPowerFixed = true;
    }
    private boolean FixTestItemPowerLevels(Iterable<OfferBundle> offers) {
        if (TestItemPowerFixed || HomeMode == null || HomeMode.Avatar == null) return false;
        boolean hasClaimedTestItem = false;
        if (offers != null) {
            for (OfferBundle bundle : offers) {
                if (bundle == null || bundle.Items == null) continue;
                boolean bundleHasTest = false;
                for (Offer offer : bundle.Items) {
                    if (offer != null && offer.IsTestItem) { bundleHasTest = true; break; }
                }
                if (!bundleHasTest) continue;
                boolean claimed = bundle.Purchased;
                if (!claimed && OffersClaimed != null && bundle.Claim != null && OffersClaimed.contains(bundle.Claim)) claimed = true;
                if (claimed) { hasClaimedTestItem = true; break; }
            }
        }
        if (!hasClaimedTestItem) return false;
        for (Hero hero : HomeMode.Avatar.Heroes) {
            if (hero == null) continue;
            CharacterData cd = hero.getCharacterData();
            if (cd == null || !cd.IsHero()) continue;
            hero.PowerLevel = 8;
            hero.PowerPoints = 1410;
        }
        TestItemPowerFixed = true;
        return true;
    }
    private static boolean IsRandomPinEligible(EmoteData emote) {
        return emote != null && !emote.Disabled && !emote.LockedForChronos && !emote.IsDefaultBattleEmote
            && emote.Character != null && !emote.Character.isBlank()
            && (emote.Skin == null || emote.Skin.isBlank())
            && (emote.EmoteBundles == null || emote.EmoteBundles.isBlank())
            && ("COMMON".equals(emote.Rarity) || "RARE".equals(emote.Rarity) || "EPIC".equals(emote.Rarity));
    }
    private List<EmoteData> GetAvailableRandomPins(Set<Integer> excludedPins) {
        if (HomeMode == null || HomeMode.Home == null || HomeMode.Avatar == null || HomeMode.Avatar.Heroes == null) return new ArrayList<>();
        if (HomeMode.Home.UnlockedEmotes == null) HomeMode.Home.UnlockedEmotes = new ArrayList<>();
        Set<Integer> unlockedPins = new HashSet<>(HomeMode.Home.UnlockedEmotes);
        Set<String> unlockedCharacters = new HashSet<>();
        for (Hero hero : HomeMode.Avatar.Heroes) {
            if (hero == null) continue;
            CharacterData characterData = hero.getCharacterData();
            if (characterData != null) unlockedCharacters.add(characterData.Name);
        }
        List<EmoteData> result = new ArrayList<>();
        for (LogicData d : DataTables.Get(DataType.Emote).GetDatas()) {
            if (!(d instanceof EmoteData emote)) continue;
            if (!IsRandomPinEligible(emote)) continue;
            if (!unlockedCharacters.contains(emote.Character)) continue;
            if (unlockedPins.contains(emote.GetGlobalId())) continue;
            if (excludedPins != null && excludedPins.contains(emote.GetGlobalId())) continue;
            result.add(emote);
        }
        return result;
    }
    public boolean TryAddPinPackDrops(DeliveryUnit unit, Set<Integer> excludedPins) {
        return TryAddPinPackDrops(unit, excludedPins, null);
    }
    boolean TryAddPinPackDrops(DeliveryUnit unit, Set<Integer> excludedPins, Random rng) {
        if (unit == null) return false;
        List<EmoteData> availablePins = GetAvailableRandomPins(excludedPins);
        List<EmoteData> commonPins = new ArrayList<>();
        List<EmoteData> rarePins = new ArrayList<>();
        List<EmoteData> epicPins = new ArrayList<>();
        for (EmoteData e : availablePins) {
            if ("COMMON".equals(e.Rarity)) commonPins.add(e);
            else if ("RARE".equals(e.Rarity)) rarePins.add(e);
            else if ("EPIC".equals(e.Rarity)) epicPins.add(e);
        }
        if (commonPins.size() < 2 || (rarePins.isEmpty() && epicPins.isEmpty())) return false;
        if (rng == null) rng = SHARED_RANDOM;
        Set<String> usedCharacters = new HashSet<>();
        List<EmoteData> bonusPins = rng.nextInt(100) < 90 ? rarePins : epicPins;
        if (bonusPins.isEmpty()) bonusPins = !rarePins.isEmpty() ? rarePins : epicPins;
        int[] pins = new int[]{pickPin(commonPins, usedCharacters, rng), pickPin(commonPins, usedCharacters, rng), pickPin(bonusPins, usedCharacters, rng)};
        for (int pin : pins) {
            GatchaDrop drop = new GatchaDrop(11);
            drop.PinGlobalId = pin;
            drop.Count = 1;
            unit.AddDrop(drop);
        }
        return true;
    }
    private static int pickPin(List<EmoteData> list, Set<String> usedCharacters, Random rng) {
        List<EmoteData> distinctPins = new ArrayList<>();
        for (EmoteData e : list) {
            if (!usedCharacters.contains(e.Character)) distinctPins.add(e);
        }
        List<EmoteData> candidates = !distinctPins.isEmpty() ? distinctPins : list;
        EmoteData selected = candidates.get(rng.nextInt(candidates.size()));
        list.remove(selected);
        usedCharacters.add(selected.Character);
        return selected.GetGlobalId();
    }
    private boolean TryAddPinPackDropsOfRarity(DeliveryUnit unit, int rarity, int count) {
        if (unit == null) return false;
        List<Integer> availablePins = new ArrayList<>();
        for (EmoteData emote : GetAvailableRandomPins(null)) {
            if (emote.getRarityId() == rarity) availablePins.add(emote.GetGlobalId());
        }
        if (availablePins.isEmpty()) return false;
        Random r = new Random();
        int toGive = Math.min(Math.max(1, count), availablePins.size());
        for (int i = 0; i < toGive; i++) {
            int idx = r.nextInt(availablePins.size());
            int pinId = availablePins.get(idx);
            availablePins.remove(idx);
            GatchaDrop drop = new GatchaDrop(11);
            drop.PinGlobalId = pinId;
            drop.Count = 1;
            unit.AddDrop(drop);
        }
        return unit.GetDrops().length > 0;
    }
    private boolean TryResolveOfferEmote(Offer offer, EmoteData[] emoteDataOut, int[] emoteGlobalIdOut) {
        emoteDataOut[0] = null;
        emoteGlobalIdOut[0] = 0;
        if (offer == null) return false;
        if (offer.ItemDataId != 0) {
            EmoteData emoteData = DataTables.Get(DataType.Emote).GetDataByGlobalId(offer.ItemDataId);
            if (emoteData == null) emoteData = (EmoteData) DataTables.Get(DataType.Emote).GetDataWithId(offer.ItemDataId);
            if (emoteData != null) {
                emoteDataOut[0] = emoteData;
                emoteGlobalIdOut[0] = emoteData.GetGlobalId();
                return true;
            }
        }
        if (offer.SkinDataId != 0) {
            EmoteData emoteData = DataTables.Get(DataType.Emote).GetDataByGlobalId(offer.SkinDataId);
            if (emoteData == null) emoteData = (EmoteData) DataTables.Get(DataType.Emote).GetDataWithId(offer.SkinDataId);
            if (emoteData != null) {
                emoteDataOut[0] = emoteData;
                emoteGlobalIdOut[0] = emoteData.GetGlobalId();
                return true;
            }
        }
        return false;
    }
    private static String GetOfferIdentity(OfferBundle bundle) {
        if (bundle != null && bundle.Claim != null && !bundle.Claim.isEmpty()) return "claim:" + bundle.Claim;
        if (bundle != null && bundle.Title != null && !bundle.Title.isEmpty()) return "title:" + bundle.Title;
        return "fallback:" + BuildOfferSignature(bundle);
    }
    private static Map<String, OfferBundle> BuildOfferDictionary(Iterable<OfferBundle> bundles) {
        Map<String, OfferBundle> dictionary = new LinkedHashMap<>();
        if (bundles == null) return dictionary;
        for (OfferBundle bundle : bundles) {
            if (bundle == null) continue;
            dictionary.put(GetOfferIdentity(bundle), bundle);
        }
        return dictionary;
    }
    private static class SkinOffersFile {
        public Instant EndTime = Instant.EPOCH;
        public Map<String, Integer> conf;
        public List<OfferBundle> offers;
    }
    private static final Map<String, Integer> SkinOfferConfAliases = new HashMap<>();
    private static volatile Map<Integer, Set<String>> SkinSectionCampaigns;
    static {
        SkinOfferConfAliases.put("skinsectionid", 29);
        SkinOfferConfAliases.put("createskingroupcampaignitem", 36);
        SkinOfferConfAliases.put("usebigofferforskinbundle", 25);
        SkinOfferConfAliases.put("enablebigoffer", 59);
    }
    private static boolean TryResolveConfKey(String raw, int[] keyOut) {
        keyOut[0] = 0;
        if (raw != null) {
            try {
                keyOut[0] = Integer.parseInt(raw.trim());
                return true;
            } catch (NumberFormatException ignored) {
            }
        }
        String normalized = raw == null ? "" : raw.trim().toLowerCase(Locale.ROOT);
        Integer v = SkinOfferConfAliases.get(normalized);
        if (v != null) {
            keyOut[0] = v;
            return true;
        }
        return false;
    }
    private static SkinOffersFile LoadSkinOffersFile() {
        try {
            Path path = Path.of("JSON/skin_offers.json");
            if (!Files.exists(path)) return null;
            SkinOffersFile file = JsonUtil.FromJson(Files.readString(path), SkinOffersFile.class);
            if (file == null) System.out.println("[Shop] skin_offers.json could not be parsed");
            else if (file.offers != null) {
                int section = GetConfiguredSkinOfferSectionId(file);
                Set<String> campaigns = section <= 0 ? Set.of() : GetSkinSectionCampaigns().getOrDefault(section, Set.of());
                for (OfferBundle bundle : file.offers) {
                    if (bundle == null) continue;
                    boolean disabled = bundle.EndTime == null || bundle.EndTime.equals(Instant.EPOCH);
                    bundle.EndTime = disabled || !MatchesSkinOfferSection(bundle, campaigns) || file.EndTime == null
                        ? Instant.EPOCH : file.EndTime;
                    ApplySkinOfferCsvPrice(bundle);
                }
            }
            return file;
        } catch (Exception ex) {
            System.out.println("[Shop] skin_offers.json load failed: " + ex.getMessage());
            return null;
        }
    }
    private static Map<Integer, Set<String>> GetSkinSectionCampaigns() throws java.io.IOException {
        Map<Integer, Set<String>> campaigns = SkinSectionCampaigns;
        if (campaigns != null) return campaigns;
        synchronized (ClientHome.class) {
            campaigns = SkinSectionCampaigns;
            if (campaigns != null) return campaigns;
            Table table = new Table("SavBrawl/Logic/Assets/csv_logic/seasonal_skin_sections.csv");
            Map<Integer, Set<String>> sections = new HashMap<>();
            for (int i = 0; i < table.GetRowCount(); i++) {
                Row row = table.GetRowAt(i);
                int section = Integer.parseInt(row.GetValue("Mode", 0));
                Set<String> included = new HashSet<>();
                for (int index = 0; index < row.GetArraySize("IncludedCampaigns"); index++) {
                    String campaign = row.GetValue("IncludedCampaigns", index);
                    if (campaign != null && !campaign.isBlank()) included.add(campaign.trim());
                }
                sections.put(section, Set.copyOf(included));
            }
            SkinSectionCampaigns = campaigns = Map.copyOf(sections);
            return campaigns;
        }
    }
    private static boolean MatchesSkinOfferSection(OfferBundle bundle, Set<String> campaigns) {
        if (campaigns.isEmpty() || bundle.Items == null || bundle.Items.isEmpty()) return false;
        DataTable skins = DataTables.Get(DataType.Skin);
        if (skins == null) return false;
        for (Offer item : bundle.Items) {
            if (item == null || item.Type != ShopItem.Skin) return false;
            SkinData skin = skins.GetDataByGlobalId(GlobalId.CreateGlobalId(29, item.SkinDataId));
            if (skin == null) return false;
            Row row = skin.GetCSVRow();
            boolean matches = false;
            for (int index = 0; index < row.GetArraySize("Campaigns"); index++) {
                String campaign = row.GetValue("Campaigns", index);
                if (campaign != null && campaigns.contains(campaign.trim())) { matches = true; break; }
            }
            if (!matches) return false;
        }
        return true;
    }
    private static void ApplySkinOfferCsvPrice(OfferBundle bundle) {
        if (bundle == null || bundle.IsBillingOffer() || bundle.Cost < 0 || bundle.Items == null || bundle.Items.isEmpty()) return;
        DataTable skins = DataTables.Get(DataType.Skin);
        if (skins == null) return;
        long csvCost = 0;
        for (Offer item : bundle.Items) {
            if (item == null || item.Type != ShopItem.Skin) return;
            SkinData skin = skins.GetDataByGlobalId(GlobalId.CreateGlobalId(29, item.SkinDataId));
            if (skin == null) return;
            int price = switch (bundle.Currency) {
                case 0 -> skin.CostGems;
                case 1 -> skin.CostCoins;
                case 3 -> skin.CostStarPoints;
                default -> 0;
            };
            if (price <= 0) return;
            csvCost += price;
            if (csvCost > Integer.MAX_VALUE) return;
        }
        if (bundle.Cost == 0) bundle.Cost = (int)csvCost;
        bundle.OldCost = bundle.Cost < csvCost ? (int)csvCost : 0;
    }
    private static int GetConfiguredSkinOfferSectionId(SkinOffersFile file) {
        if (file == null || file.conf == null) return 0;
        int section = 0;
        for (Map.Entry<String, Integer> kv : file.conf.entrySet()) {
            int[] key = new int[1];
            if (kv.getValue() != null && TryResolveConfKey(kv.getKey(), key) && key[0] == 29) section = kv.getValue();
        }
        return Math.max(0, section);
    }
    private static int GetSkinOfferBannerSectionId(SkinOffersFile file, Instant time) {
        if (file == null || file.EndTime == null || !file.EndTime.isAfter(time)) return 0;
        return GetConfiguredSkinOfferSectionId(file);
    }
    private static String GetSkinOfferBannerSignature(SkinOffersFile file, Instant time) {
        return file == null ? "disabled" : GetSkinOfferBannerSectionId(file, time) + "|" + file.EndTime + "|" + file.conf;
    }
    private static void SetLogicConfValue(List<Integer> logicConfData, int key, int value) {
        for (int i = 0; i + 1 < logicConfData.size(); i += 2) {
            if (logicConfData.get(i) == key) {
                logicConfData.set(i + 1, value);
                return;
            }
        }
        logicConfData.add(key);
        logicConfData.add(value);
    }
    private static int ApplySkinOfferConf(List<Integer> logicConfData, SkinOffersFile file, Instant time) {
        Map<String, Integer> conf = file == null ? null : file.conf;
        if (conf != null) for (Map.Entry<String, Integer> kv : conf.entrySet()) {
            if (kv.getValue() == null) continue;
            int[] keyOut = new int[1];
            if (!TryResolveConfKey(kv.getKey(), keyOut)) {
                System.out.println("[Shop] skin_offers.json: unknown conf key '" + kv.getKey() + "', skipped");
                continue;
            }
            SetLogicConfValue(logicConfData, keyOut[0], kv.getValue());
        }
        int section = GetSkinOfferBannerSectionId(file, time);
        SetLogicConfValue(logicConfData, 29, section);
        if (section <= 0) SetLogicConfValue(logicConfData, 36, 0);
        return section;
    }
    private static String BuildOfferSignature(OfferBundle bundle) {
        if (bundle == null) return "";
        StringBuilder sb = new StringBuilder();
        sb.append(bundle.Title).append("|").append(bundle.Claim).append("|").append(bundle.Cost).append("|").append(bundle.Currency).append("|");
        sb.append(bundle.EndTime).append("|").append(bundle.StartTime).append("|").append(bundle.BackgroundExportName).append("|").append(bundle.OldCost).append("|");
        sb.append(bundle.IsDailyDeals).append("|").append(bundle.isDonateOffer).append("|");
        sb.append(bundle.SaleStyle).append("|").append(bundle.SaleAmount).append("|");
        if (bundle.Items != null) {
            for (Offer item : bundle.Items) {
                if (item == null) continue;
                sb.append(item.Type).append(",").append(item.IsTestItem).append(",").append(item.Count).append(",").append(item.ItemDataId).append(",").append(item.SkinDataId).append(";");
            }
        }
        return sb.toString();
    }
    private boolean CanOfferSkin(Offer item) {
        if (item == null || HomeMode == null || HomeMode.Avatar == null) return false;
        int skinGlobalId = GlobalId.CreateGlobalId(29, item.SkinDataId);
        DataTable skinTable = DataTables.Get(DataType.Skin);
        SkinData skinData = skinTable == null ? null : skinTable.GetDataByGlobalId(skinGlobalId);
        SkinConfData skinConfData = skinData == null ? null : skinData.GetConf();
        if (skinConfData == null || skinConfData.Character == null || skinConfData.Character.isBlank()) return false;
        CharacterData characterData = DataTables.Get(DataType.Character) == null ? null : DataTables.Get(DataType.Character).GetData(skinConfData.Character);
        return characterData != null && HomeMode.Avatar.HasHero(characterData.GetGlobalId())
            && !(UnlockedSkins != null && UnlockedSkins.contains(skinGlobalId))
            && IsRankedShopSkinUnlocked(skinGlobalId);
    }
    private boolean ShouldSkipJsonOfferBundle(OfferBundle bundle, Instant time) {
        if (bundle == null) return true;
        if (bundle.Claim != null && !bundle.Claim.isEmpty() && OffersClaimed != null && OffersClaimed.contains(bundle.Claim)) return true;
        if (bundle.EndTime != null && !bundle.EndTime.isAfter(time)) return true;
        if (bundle.StartTime != null && bundle.StartTime.isAfter(time)) return true;
        if (bundle.AllowedAccountIds != null && !bundle.AllowedAccountIds.isEmpty()
            && (HomeMode == null || HomeMode.Avatar == null || !bundle.AllowedAccountIds.contains(HomeMode.Avatar.AccountId))) return true;
        if (bundle.Items == null || bundle.Items.isEmpty()) return true;
        for (Offer item : bundle.Items) {
            try {
                if (item == null) continue;
                if (item.Type == ShopItem.Skin) {
                    if (!CanOfferSkin(item)) return true;
                }
                if (item.Type == ShopItem.GuaranteedHero) {
                    if (HomeMode.Avatar.HasHero(item.ItemDataId)) return true;
                }
                if (item.Type == ShopItem.Emote) {
                    EmoteData[] emoteDataOut = new EmoteData[1];
                    int[] emoteGlobalIdOut = new int[1];
                    if (!TryResolveOfferEmote(item, emoteDataOut, emoteGlobalIdOut)) return true;
                    EmoteData emoteData = emoteDataOut[0];
                    int emoteGlobalId = emoteGlobalIdOut[0];
                    if (HomeMode.Home.UnlockedEmotes.contains(emoteGlobalId)) return true;
                    if (emoteData.Character != null && !emoteData.Character.isEmpty()) {
                        CharacterData characterData = DataTables.Get(DataType.Character).GetData(emoteData.Character);
                        if (characterData != null && !HomeMode.Avatar.HasHero(characterData.GetGlobalId())) return true;
                    }
                }
            } catch (Exception e) {
                System.out.println("item error: " + e.getMessage());
                return true;
            }
        }
        return bundle.Purchased;
    }
    private void RotateShopContent(Instant time, boolean isNewAcc) {
        if (OfferBundles == null) OfferBundles = new ArrayList<>();
        SkinOffersFile skinFile = LoadSkinOffersFile();
        String bannerSignature = GetSkinOfferBannerSignature(skinFile, time);
        boolean skinBannerChanged = !Objects.equals(SkinOfferBannerSignature, bannerSignature);
        SkinOfferBannerSignature = bannerSignature;
        boolean questsUpdated = RefreshQuestsIfNeeded(time);
        questsUpdated = SyncSpecialQuestsIfNeeded(time) || questsUpdated;
        boolean offersUpdated = FixTestItemPowerLevels(OfferBundles);
        int offLen = OfferBundles.size();
        int removedExpiredCount = 0;
        List<OfferBundle> toRemoveExpired = new ArrayList<>();
        for (OfferBundle offer : OfferBundles) {
            if (offer == null) { toRemoveExpired.add(offer); continue; }
            boolean expired = offer.EndTime != null && !offer.EndTime.isAfter(time);
            boolean skinInvalid = false;
            boolean autoHeroOwned = false;
            if (offer.Items != null) {
                for (Offer item : offer.Items) {
                    if (item != null && item.Type == ShopItem.Skin && !CanOfferSkin(item)) { skinInvalid = true; break; }
                    if (offer.IsAutoOffer && item != null && item.Type == ShopItem.GuaranteedHero
                        && HomeMode != null && HomeMode.Avatar != null && HomeMode.Avatar.HasHero(item.ItemDataId)) autoHeroOwned = true;
                }
            }
            if (expired || skinInvalid || autoHeroOwned) toRemoveExpired.add(offer);
        }
        removedExpiredCount = toRemoveExpired.size();
        OfferBundles.removeAll(toRemoveExpired);
        if (removedExpiredCount > 0) offersUpdated = true;
        try {
            String json = Files.readString(Path.of("JSON/offers.json"));
            OfferBundle[] parsedBundles = JsonUtil.FromJson(json, OfferBundle[].class);
            if (parsedBundles == null) throw new IllegalArgumentException("offers.json could not be parsed");
            List<OfferBundle> bundlesFromJson = new ArrayList<>(Arrays.asList(parsedBundles));
            offersUpdated = FixTestItemPowerLevels(bundlesFromJson) || offersUpdated;
            List<OfferBundle> activeJsonBundles = new ArrayList<>();
            for (OfferBundle b : bundlesFromJson) {
                if (!ShouldSkipJsonOfferBundle(b, time)) activeJsonBundles.add(b);
            }
            List<OfferBundle> skinFileOffers = skinFile == null ? null : skinFile.offers;
            if (skinFileOffers != null) {
                for (OfferBundle b : skinFileOffers) {
                    if (!ShouldSkipJsonOfferBundle(b, time)) activeJsonBundles.add(b);
                }
            }
            List<OfferBundle> nonDailyExisting = new ArrayList<>();
            for (OfferBundle o : OfferBundles) {
                if (o != null && !o.IsDailyDeals && !o.IsDailySkins && !o.IsAutoOffer) nonDailyExisting.add(o);
            }
            Map<String, OfferBundle> existingNonDaily = BuildOfferDictionary(nonDailyExisting);
            Map<String, OfferBundle> incomingNonDaily = BuildOfferDictionary(activeJsonBundles);
            List<String> toDeleteKeys = new ArrayList<>();
            for (String key : existingNonDaily.keySet()) {
                OfferBundle existing = existingNonDaily.get(key);
                boolean personalDonateOffer = existing.isDonateOffer
                    && (existing.Claim == null || existing.Claim.isBlank());
                if (!incomingNonDaily.containsKey(key) && !personalDonateOffer)
                    toDeleteKeys.add(key);
            }
            for (String key : toDeleteKeys) {
                OfferBundles.remove(existingNonDaily.get(key));
                offersUpdated = true;
            }
            for (Map.Entry<String, OfferBundle> incoming : incomingNonDaily.entrySet()) {
                OfferBundle existing = existingNonDaily.get(incoming.getKey());
                if (existing == null) {
                    OfferBundles.add(incoming.getValue());
                    offersUpdated = true;
                    continue;
                }
                if (!BuildOfferSignature(existing).equals(BuildOfferSignature(incoming.getValue()))) {
                    incoming.getValue().State = existing.State;
                    incoming.getValue().Purchased = existing.Purchased;
                    int existingIndex = OfferBundles.indexOf(existing);
                    if (existingIndex >= 0) {
                        OfferBundles.set(existingIndex, incoming.getValue());
                        offersUpdated = true;
                    }
                }
            }
        } catch (Exception ex) {
            System.out.println("Error of loading offers.json: " + ex);
        }
        boolean skinPurchaseMarked = UpdatePurchasedSkinOffers();
        offersUpdated = offersUpdated || OfferBundles.size() != offLen || skinPurchaseMarked;
        if (isNewAcc || LocalDateTime.ofInstant(Instant.now(), ZoneOffset.UTC).getHour() >= 8) {
            if (LastRotateDate == null || truncateToDay(LastRotateDate).isBefore(truncateToDay(Instant.now()))) {
                offersUpdated = true;
                OfferBundles.removeIf(offer -> offer != null && (offer.IsDailyDeals || offer.IsDailySkins));
                LastRotateDate = truncateToDay(Instant.now());
                UpdateDailyOfferBundles();
                UpdateDailySkins();
                PowerPlayGamesPlayed = 0;
                ReportsIds = new ArrayList<>();
            }
        }
        if (OfferBundles == null) {
            UpdateDailyOfferBundles();
            offersUpdated = true;
        } else if (OfferBundles.isEmpty()) {
            UpdateDailyOfferBundles();
            offersUpdated = true;
        }
        Instant autoShopRotation = GetAutoShopRotationStart(time);
        if (HomeMode != null && HomeMode.Avatar != null
            && (LastAutoShopRefreshDate == null || LastAutoShopRefreshDate.isBefore(autoShopRotation))) {
            OfferBundles.removeIf(offer -> offer != null && offer.IsAutoOffer);
            OfferBundles.addAll(GenerateAutoShopOffers(HomeMode.Avatar, autoShopRotation, SHARED_RANDOM));
            LastAutoShopRefreshDate = autoShopRotation;
            offersUpdated = true;
        }
        if (offersUpdated && HomeMode != null && HomeMode.GameListener != null && HomeDataLoaded) {
            AvailableServerCommandMessage offersUpdatedMessage = new AvailableServerCommandMessage();
            LogicOffersChangedCommand cmd = new LogicOffersChangedCommand();
            cmd.OfferBundles = OfferBundles;
            offersUpdatedMessage.Command = cmd;
            HomeMode.GameListener.SendMessage(offersUpdatedMessage);
        }
        if ((questsUpdated || skinBannerChanged && HomeDataLoaded) && HomeMode != null && HomeMode.GameListener != null) {
            LogicDayChangedCommand newday = new LogicDayChangedCommand();
            newday.Home = this;
            newday.Home.Events = Events;
            AvailableServerCommandMessage eventupdated = new AvailableServerCommandMessage();
            eventupdated.Command = newday;
            HomeMode.GameListener.SendMessage(eventupdated);
        }
    }
    private boolean RefreshQuestsIfNeeded(Instant time) {
        if (TrophyRoadProgress < 11) return false;
        Instant seasonStartUtc = GetBrawlPassSeasonStartUtc(time);
        if (Quests == null || (QuestSeasonStartDate != null && QuestSeasonStartDate.isBefore(seasonStartUtc))) {
            EnsureQuestsForCurrentSeason(time);
            return true;
        }
        if (Quests.QuestList == null) Quests.QuestList = new ArrayList<>();
        if (LastQuestRefreshDate == null || LastQuestRefreshDate.equals(MIN_INSTANT) || LastQuestRefreshDate.equals(Instant.EPOCH)) {
            if (LastRotateDate != null && yearOf(LastRotateDate) > 2000 && !LastRotateDate.isBefore(seasonStartUtc)) {
                LastQuestRefreshDate = truncateToDay(LastRotateDate);
            } else {
                LastQuestRefreshDate = truncateToDay(seasonStartUtc);
            }
        }
        Duration refreshTime = QUEST_REFRESH_TIME_UTC;
        Instant lastAppliedDate = truncateToDay(LastQuestRefreshDate);
        Instant cursor = lastAppliedDate.plus(Duration.ofDays(1));
        int dailyRefreshes = 0;
        int regularRefreshes = 0;
        Instant timeDay = truncateToDay(time);
        while (!cursor.isAfter(timeDay)) {
            boolean timeReached = cursor.isBefore(timeDay) || Duration.between(timeDay, time).compareTo(refreshTime) >= 0;
            if (timeReached) {
                dailyRefreshes++;
                DayOfWeek dow = LocalDateTime.ofInstant(cursor, ZoneOffset.UTC).getDayOfWeek();
                if (dow == DayOfWeek.TUESDAY || dow == DayOfWeek.THURSDAY) regularRefreshes++;
                lastAppliedDate = cursor;
            }
            cursor = cursor.plus(Duration.ofDays(1));
        }
        boolean updated = false;
        if (dailyRefreshes > 0 || regularRefreshes > 0) {
            Object questLock = Quests.getQuestListLock();
            synchronized (questLock) {
                if (dailyRefreshes > 0) {
                    Quests.QuestList.removeIf(q -> q != null && q.IsDailyQuest);
                    Quests.AddDailyQuests(HomeMode.Avatar.Heroes);
                    updated = true;
                }
                if (regularRefreshes > 0) {
                    for (int i = 0; i < regularRefreshes; i++) {
                        Quests.AddNonDailyQuests(HomeMode.Avatar.Heroes);
                    }
                    updated = true;
                }
            }
        }
        if (updated) {
            LastQuestRefreshDate = lastAppliedDate;
            return true;
        }
        return false;
    }
    private boolean SyncSpecialQuestsIfNeeded(Instant time) {
        if (TrophyRoadProgress < 11) return false;
        if (Quests == null) Quests = new Quests();
        if (Quests.QuestList == null) Quests.QuestList = new ArrayList<>();
        if (GrantedSpecialQuestIds == null) GrantedSpecialQuestIds = new ArrayList<>();
        List<?> definitions = SpecialQuestStore.LoadDefinitions();
        Set<String> activeDefinitionIds = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        if (definitions != null) {
            for (Object defObj : definitions) {
                if (defObj == null) continue;
                String id = reflString(defObj, "Id");
                Instant end = reflInstant(defObj, "EndTimeUtc");
                if (id == null || id.isBlank()) continue;
                if (end == null || !end.isAfter(time)) continue;
                activeDefinitionIds.add(id);
            }
        }
        boolean changed = false;
        synchronized (Quests.getQuestListLock()) {
            List<Quest> snapshot = new ArrayList<>(Quests.QuestList);
            for (Quest quest : snapshot) {
                if (quest == null || !quest.IsManualSpecialQuest) continue;
                if (quest.ManualSpecialQuestId == null || quest.ManualSpecialQuestId.isBlank()) {
                    Quests.QuestList.remove(quest);
                    changed = true;
                    continue;
                }
                Object definition = findSpecialDefinition(definitions, quest.ManualSpecialQuestId, time);
                boolean hasHero = quest.CharacterId == 0 || (HomeMode != null && HomeMode.Avatar != null && HomeMode.Avatar.HasHero(quest.CharacterId));
                if (definition == null || !hasHero) {
                    Quests.QuestList.remove(quest);
                    changed = true;
                    continue;
                }
                Instant defEnd = reflInstant(definition, "EndTimeUtc");
                if (quest.ManualSpecialQuestEndTimeUtc == null || !quest.ManualSpecialQuestEndTimeUtc.equals(defEnd)) {
                    quest.ManualSpecialQuestEndTimeUtc = defEnd;
                    changed = true;
                }
                if (quest.ClientQuestType < 0) {
                    quest.ClientQuestType = 0;
                    changed = true;
                }
                if (!ContainsSpecialQuestId(quest.ManualSpecialQuestId)) {
                    GrantedSpecialQuestIds.add(quest.ManualSpecialQuestId);
                    changed = true;
                }
            }
            if (definitions != null) {
                for (Object defObj : definitions) {
                    if (defObj == null) continue;
                    String id = reflString(defObj, "Id");
                    Instant end = reflInstant(defObj, "EndTimeUtc");
                    int charId = reflInt(defObj, "CharacterId");
                    if (id == null || id.isBlank()) continue;
                    if (end == null || !end.isAfter(time)) continue;
                    if (ContainsSpecialQuestId(id)) continue;
                    if (charId != 0 && !(HomeMode != null && HomeMode.Avatar != null && HomeMode.Avatar.HasHero(charId))) continue;
                    boolean alreadyListed = false;
                    for (Quest q : Quests.QuestList) {
                        if (q != null && q.IsManualSpecialQuest && q.ManualSpecialQuestId != null && q.ManualSpecialQuestId.equalsIgnoreCase(id)) { alreadyListed = true; break; }
                    }
                    if (alreadyListed) {
                        GrantedSpecialQuestIds.add(id);
                        changed = true;
                        continue;
                    }
                    Quest created = reflCreateQuest(defObj);
                    if (created == null) continue;
                    Quests.QuestList.add(created);
                    GrantedSpecialQuestIds.add(id);
                    changed = true;
                }
            }
        }
        List<String> toRemoveGranted = new ArrayList<>();
        for (String gid : GrantedSpecialQuestIds) {
            if (gid == null || gid.isBlank() || !containsIgnoreCase(activeDefinitionIds, gid)) toRemoveGranted.add(gid);
        }
        if (!toRemoveGranted.isEmpty()) {
            GrantedSpecialQuestIds.removeAll(toRemoveGranted);
            changed = true;
        }
        return changed;
    }
    private static Object findSpecialDefinition(List<?> definitions, String questId, Instant time) {
        if (definitions == null || questId == null) return null;
        for (Object defObj : definitions) {
            if (defObj == null) continue;
            String id = reflString(defObj, "Id");
            Instant end = reflInstant(defObj, "EndTimeUtc");
            if (id != null && id.equalsIgnoreCase(questId) && end != null && end.isAfter(time)) return defObj;
        }
        return null;
    }
    private static String reflString(Object o, String field) {
        try {
            var member = o.getClass().getField(field); member.setAccessible(true);
            Object v = member.get(o);
            return v == null ? null : v.toString();
        } catch (Exception e) {
            return null;
        }
    }
    private static Instant reflInstant(Object o, String field) {
        try {
            var member = o.getClass().getField(field); member.setAccessible(true);
            Object v = member.get(o);
            return v instanceof Instant ? (Instant) v : null;
        } catch (Exception e) {
            return null;
        }
    }
    private static int reflInt(Object o, String field) {
        try {
            var member = o.getClass().getField(field); member.setAccessible(true);
            Object v = member.get(o);
            return v instanceof Integer ? (Integer) v : 0;
        } catch (Exception e) {
            return 0;
        }
    }
    private static Quest reflCreateQuest(Object o) {
        try {
            var method = o.getClass().getMethod("CreateQuest"); method.setAccessible(true);
            Object v = method.invoke(o);
            return v instanceof Quest ? (Quest) v : null;
        } catch (Exception e) {
            return null;
        }
    }
    private static boolean containsIgnoreCase(Set<String> set, String value) {
        for (String s : set) {
            if (s != null && s.equalsIgnoreCase(value)) return true;
        }
        return false;
    }
    private boolean ContainsSpecialQuestId(String questId) {
        if (questId == null || questId.isBlank() || GrantedSpecialQuestIds == null) return false;
        for (String id : GrantedSpecialQuestIds) {
            if (id != null && id.equalsIgnoreCase(questId)) return true;
        }
        return false;
    }
    private static Instant GetBrawlPassSeasonStartUtc(Instant time) {
        return BrawlPassSeasonConfig.SeasonStartUtc();
    }
    public static int GetSecondsUntilNextQuestRefresh(Instant time) {
        Instant nextRefreshUtc = truncateToDay(time).plus(QUEST_REFRESH_TIME_UTC);
        if (Duration.between(truncateToDay(time), time).compareTo(QUEST_REFRESH_TIME_UTC) >= 0) {
            nextRefreshUtc = nextRefreshUtc.plus(Duration.ofDays(1));
        }
        return Math.max(1, (int) Math.ceil((double) Duration.between(time, nextRefreshUtc).getSeconds()));
    }
    public static int GetSecondsUntilNextRegularQuestRefresh(Instant time) {
        Instant candidate = truncateToDay(time).plus(QUEST_REFRESH_TIME_UTC);
        DayOfWeek dow = LocalDateTime.ofInstant(candidate, ZoneOffset.UTC).getDayOfWeek();
        boolean isTueThu = dow == DayOfWeek.TUESDAY || dow == DayOfWeek.THURSDAY;
        if (!candidate.isAfter(time) || !isTueThu) candidate = candidate.plus(Duration.ofDays(1));
        while (true) {
            DayOfWeek d = LocalDateTime.ofInstant(candidate, ZoneOffset.UTC).getDayOfWeek();
            if (d == DayOfWeek.TUESDAY || d == DayOfWeek.THURSDAY) break;
            candidate = candidate.plus(Duration.ofDays(1));
        }
        return Math.max(1, (int) Math.ceil((double) Duration.between(time, candidate).getSeconds()));
    }
    private static Instant GetBrawlPassSeasonEndUtc(Instant time) {
        return BrawlPassSeasonConfig.SeasonEndUtc();
    }
    private static int CountRegularQuestRefreshesSinceSeasonStart(Instant seasonStartUtc, Instant time) {
        int regularRefreshes = 0;
        Instant cursor = truncateToDay(seasonStartUtc).plus(Duration.ofDays(1));
        Instant timeDay = truncateToDay(time);
        while (!cursor.isAfter(timeDay)) {
            boolean timeReached = cursor.isBefore(timeDay) || Duration.between(timeDay, time).compareTo(QUEST_REFRESH_TIME_UTC) >= 0;
            if (timeReached) {
                DayOfWeek dow = LocalDateTime.ofInstant(cursor, ZoneOffset.UTC).getDayOfWeek();
                if (dow == DayOfWeek.TUESDAY || dow == DayOfWeek.THURSDAY) regularRefreshes++;
            }
            cursor = cursor.plus(Duration.ofDays(1));
        }
        return regularRefreshes;
    }
    private boolean UpdatePurchasedSkinOffers() {
        boolean marked = false;
        if (OfferBundles == null) return false;
        for (OfferBundle bundle : OfferBundles) {
            if (bundle == null || bundle.Purchased) continue;
            if (bundle.Items == null) continue;
            for (Offer item : bundle.Items) {
                if (item == null || item.Type != ShopItem.Skin) continue;
                int skinGlobalId = item.SkinDataId + 29000000;
                if (UnlockedSkins != null && UnlockedSkins.contains(skinGlobalId)) {
                    bundle.Purchased = true;
                    marked = true;
                    break;
                }
            }
        }
        return marked;
    }
    private void UpdateDailySkins() {
        if (HomeMode == null || HomeMode.Avatar == null || HomeMode.Avatar.Heroes == null) return;
        if (UnlockedSkins == null) UnlockedSkins = new ArrayList<>();
        if (OfferBundles == null) OfferBundles = new ArrayList<>();
        if (TrueSilverSkinsUnlockedAt == null) TrueSilverSkinsUnlockedAt = new HashMap<>();
        Duration trueGoldUnlockDelay = Duration.ofDays(1);
        Set<Integer> candidateSkins = new HashSet<>();
        List<LogicData> allSkins = DataTables.Get(DataType.Skin).GetDatas();
        for (Hero hero : HomeMode.Avatar.Heroes) {
            if (hero == null) continue;
            CharacterData character = DataTables.Get(DataType.Character).GetDataByGlobalId(hero.CharacterId);
            if (character == null) continue;
            boolean hasTrueSilverUnlocked = false;
            Instant trueSilverUnlockedAt = null;
            for (LogicData d : allSkins) {
                if (!(d instanceof SkinData skin)) continue;
                if (skin == null) continue;
                if (!IsDailySkinEligible(skin)) continue;
                if (skin.CostCoins != 10000) continue;
                if (skin.ObtainType != 0) continue;
                if (skin.Disabled) continue;
                SkinConfData conf = skin.GetConf();
                if (conf == null || !conf.IsForCharacter(character)) continue;
                int silverSkinGlobalId = skin.GetGlobalId();
                if (!UnlockedSkins.contains(silverSkinGlobalId)) continue;
                hasTrueSilverUnlocked = true;
                Instant unlockedAt = TrueSilverSkinsUnlockedAt.get(silverSkinGlobalId);
                if (unlockedAt != null && (trueSilverUnlockedAt == null || unlockedAt.isAfter(trueSilverUnlockedAt))) {
                    trueSilverUnlockedAt = unlockedAt;
                }
            }
            boolean canShowTrueGold = hasTrueSilverUnlocked && (trueSilverUnlockedAt == null || !Instant.now().isBefore(trueSilverUnlockedAt.plus(trueGoldUnlockDelay)));
            for (LogicData d : allSkins) {
                if (!(d instanceof SkinData skin)) continue;
                if (skin == null) continue;
                if (!IsDailySkinEligible(skin)) continue;
                if (skin.Name != null && skin.Name.equalsIgnoreCase("SpeedBoosterDefault")) continue;
                if (skin.ObtainType != 0) continue;
                if (skin.Disabled) continue;
                if (skin.Name != null && skin.Name.toLowerCase().endsWith("default")) continue;
                SkinConfData conf = skin.GetConf();
                if (conf == null || !conf.IsForCharacter(character)) continue;
                int skinGlobalId = skin.GetGlobalId();
                if (UnlockedSkins.contains(skinGlobalId)) continue;
                if (!IsRankedShopSkinUnlocked(skinGlobalId)) continue;
                boolean isTrueGold = skin.CostCoins == 25000;
                if (isTrueGold && !canShowTrueGold) continue;
                if (skin.CostGems <= 0 && skin.CostCoins <= 0 && skin.CostStarPoints <= 0) continue;
                candidateSkins.add(skinGlobalId);
            }
        }
        if (candidateSkins.isEmpty()) return;
        Random random = new Random();
        List<Integer> candidateList = new ArrayList<>(candidateSkins);
        int offerCount = Math.min(candidateList.size(), 8);
        List<Integer> selected = new ArrayList<>();
        for (int i = 0; i < offerCount; i++) {
            int idx = random.nextInt(candidateList.size());
            selected.add(candidateList.get(idx));
            candidateList.remove(idx);
        }
        for (int skinId : selected) {
            SkinData skin = DataTables.Get(DataType.Skin).GetDataByGlobalId(skinId);
            if (skin == null) continue;
            OfferBundle bundle = new OfferBundle();
            bundle.IsDailyDeals = false;
            bundle.IsDailySkins = true;
            bundle.EndTime = truncateToDay(Instant.now()).plus(Duration.ofDays(1)).plus(Duration.ofHours(8));
            if (skin.CostGems > 0) {
                bundle.Currency = 0;
                int cost = skin.CostGems;
                if (cost == 299) cost = 199;
                else if (cost == 149) cost = 119;
                else if (cost == 79) cost = 59;
                else if (cost == 49) cost = 39;
                else if (cost == 29) cost = 19;
                bundle.Cost = cost;
                if (bundle.Cost < skin.CostGems) bundle.OldCost = skin.CostGems;
            } else if (skin.CostStarPoints > 0) {
                bundle.Currency = 3;
                bundle.Cost = skin.CostStarPoints;
            } else if (skin.CostCoins > 0) {
                bundle.Currency = 1;
                bundle.Cost = skin.CostCoins;
            } else {
                continue;
            }
            Offer offer = new Offer(ShopItem.Skin, 1);
            offer.SkinDataId = GlobalId.GetInstanceId(skinId);
            bundle.Items.add(offer);
            OfferBundles.add(bundle);
        }
    }
    private static boolean IsDailySkinEligible(SkinData skin) {
        if (skin == null || skin.LastChance) return false;
        String campaign = skin.Campaigns;
        if (campaign == null || campaign.isBlank()) return true;
        return campaign.equalsIgnoreCase("GOLD") || campaign.equalsIgnoreCase("SILVER");
    }
    private static final int AUTO_SHOP_COINS_PER_GEM = 100;
    private static final int SHOP_MIN_DISCOUNT_PERCENT = 15;
    private static final int SHOP_MAX_DISCOUNT_PERCENT = 25;
    private enum AutoShopRarity {
        RARE(29, 35),
        SUPER_RARE(79, 30),
        EPIC(169, 20),
        MYTHIC(349, 12),
        LEGENDARY(699, 3);

        final int fullCost, weight;
        AutoShopRarity(int fullCost, int weight) {
            this.fullCost = fullCost;
            this.weight = weight;
        }

        static AutoShopRarity FromCard(CardData card) {
            if (card == null || card.Rarity == null) return null;
            return switch (card.Rarity.toLowerCase(Locale.ROOT)) {
                case "rare" -> RARE;
                case "super_rare" -> SUPER_RARE;
                case "epic" -> EPIC;
                case "mega_epic", "super_epic", "mythic" -> MYTHIC;
                case "legendary" -> LEGENDARY;
                default -> null;
            };
        }
    }
    static Instant GetAutoShopRotationStart(Instant time) {
        return time.minus(Duration.ofHours(8)).truncatedTo(ChronoUnit.DAYS).plus(Duration.ofHours(8));
    }
    static int GetAutoShopCoinCost(int count) {
        if (count < 1 || count > 10000) throw new IllegalArgumentException("Coin count must be 1..10000");
        // 100 coins = 1 gem. Round up so small amounts are never free.
        return (count + AUTO_SHOP_COINS_PER_GEM - 1) / AUTO_SHOP_COINS_PER_GEM;
    }
    private static int GetShopDiscountedCost(int fullCost, Random random) {
        // Round the bounds inward to keep the real discount between 15% and 25%.
        int minCost = (fullCost * (100 - SHOP_MAX_DISCOUNT_PERCENT) + 99) / 100;
        int maxCost = fullCost * (100 - SHOP_MIN_DISCOUNT_PERCENT) / 100;
        return minCost + random.nextInt(maxCost - minCost + 1);
    }
    static List<OfferBundle> GenerateAutoShopOffers(ClientAvatar avatar, Instant rotationStart, Random random) {
        List<OfferBundle> offers = new ArrayList<>();
        int coins = (random.nextInt(100) + 1) * AUTO_SHOP_COINS_PER_GEM;
        offers.add(CreateAutoShopOffer(new Offer(ShopItem.Coin, coins), GetAutoShopCoinCost(coins), 0, rotationStart));
        int bigBoxes = random.nextInt(10 - 2 + 1) + 2;
        int megaBoxes = random.nextInt(10 - 2 + 1) + 2;
        offers.add(CreateAutoShopOffer(new Offer(ShopItem.BigBox, bigBoxes), bigBoxes * 30, 0, rotationStart));
        int megaBoxFullCost = megaBoxes * 80;
        offers.add(CreateAutoShopOffer(new Offer(ShopItem.MegaBox, megaBoxes),
            GetShopDiscountedCost(megaBoxFullCost, random), megaBoxFullCost, rotationStart));
        if (avatar == null || DataTables.Get(DataType.Character) == null || DataTables.Get(DataType.Card) == null)
            return offers;
        EnumMap<AutoShopRarity, List<CharacterData>> candidates = new EnumMap<>(AutoShopRarity.class);
        for (LogicData data : DataTables.Get(DataType.Character).GetDatas()) {
            if (!(data instanceof CharacterData character) || !character.IsHero()
                || character.Disabled || character.LockedForChronos || avatar.HasHero(character.GetGlobalId())) continue;
            CardData unlock = DataTables.GetUnlockCardFor(character);
            if (unlock == null || unlock.Disabled || unlock.LockedForChronos) continue;
            AutoShopRarity rarity = AutoShopRarity.FromCard(unlock);
            if (rarity != null) candidates.computeIfAbsent(rarity, ignored -> new ArrayList<>()).add(character);
        }
        for (int i = 0; i < 2; i++) {
            // Weight rarities rather than heroes, so the larger epic CSV pool does not dominate.
            List<AutoShopRarity> availableRarities = new ArrayList<>();
            int totalWeight = 0;
            for (AutoShopRarity rarity : candidates.keySet()) {
                if (!candidates.get(rarity).isEmpty()) {
                    availableRarities.add(rarity);
                    totalWeight += rarity.weight;
                }
            }
            if (totalWeight == 0) break;
            int roll = random.nextInt(totalWeight);
            AutoShopRarity selectedRarity = availableRarities.get(0);
            for (AutoShopRarity rarity : availableRarities) {
                selectedRarity = rarity;
                roll -= rarity.weight;
                if (roll < 0) break;
            }
            List<CharacterData> heroesOfRarity = candidates.get(selectedRarity);
            CharacterData character = heroesOfRarity.remove(random.nextInt(heroesOfRarity.size()));
            int cost = GetShopDiscountedCost(selectedRarity.fullCost, random);
            offers.add(CreateAutoShopOffer(new Offer(ShopItem.GuaranteedHero, 1, character.GetGlobalId()),
                cost, selectedRarity.fullCost, rotationStart));
        }
        return offers;
    }
    private static OfferBundle CreateAutoShopOffer(Offer item, int cost, int oldCost, Instant rotationStart) {
        OfferBundle bundle = new OfferBundle();
        bundle.IsAutoOffer = true;
        bundle.Currency = 0;
        bundle.Cost = cost;
        bundle.SetDiscount(oldCost);
        bundle.Title = "ОСОБАЯ АКЦИЯ";
        bundle.StartTime = rotationStart;
        bundle.EndTime = rotationStart.plus(Duration.ofDays(1));
        bundle.Claim = "auto-shop:" + rotationStart.getEpochSecond() + ":" + item.Type.name() + ":" + item.ItemDataId;
        bundle.Items.add(item);
        return bundle;
    }
    private void UpdateDailyOfferBundles() {
        if (OfferBundles == null) OfferBundles = new ArrayList<>();
        OfferBundles.removeIf(offer -> offer != null && offer.IsDailyDeals);
        OfferBundles.add(GenerateDailyGift());
        List<Hero> unlockedHeroes = HomeMode.Avatar.Heroes;
        List<Hero> possibleHeroes = new ArrayList<>();
        for (Hero h : unlockedHeroes) {
            if (h == null) continue;
            if (h.PowerLevel == 8) continue;
            if (h.PowerPoints >= 1410) continue;
            possibleHeroes.add(h);
        }
        Random random = new Random();
        boolean shouldPowerPoints = true;
        boolean hasMG = false;
        int offcount = 0;
        for (int i = 1; i < DAILYOFFERS_COUNT; i++) {
            if (possibleHeroes.isEmpty()) break;
            offcount++;
            if (!hasMG && random.nextInt(100) > 33) {
                i++;
                offcount++;
                hasMG = true;
                OfferBundle a = GenerateDailyOffer(false, null);
                if (a != null) OfferBundles.add(a);
            }
            int inds = random.nextInt(possibleHeroes.size());
            Hero brawler = possibleHeroes.get(inds);
            possibleHeroes.remove(inds);
            OfferBundle dailyOffer = GenerateDailyOffer(shouldPowerPoints, brawler);
            if (dailyOffer != null) {
                if (!shouldPowerPoints) shouldPowerPoints = dailyOffer.Items.get(0).Type != ShopItem.HeroPower;
                OfferBundles.add(dailyOffer);
            }
        }
        if (offcount < 5 && !hasMG) {
            OfferBundle dailyOffer = GenerateDailyOffer(false, null);
            if (dailyOffer != null) OfferBundles.add(dailyOffer);
        }
    }
    private OfferBundle GenerateDailyGift() {
        OfferBundle bundle = new OfferBundle();
        bundle.IsDailyDeals = true;
        bundle.EndTime = truncateToDay(Instant.now()).plus(Duration.ofDays(1)).plus(Duration.ofHours(8));
        bundle.Cost = 0;
        Offer offer = new Offer(ShopItem.FreeBox, 1);
        bundle.Items.add(offer);
        return bundle;
    }
    private OfferBundle GenerateDailyOffer(boolean shouldPowerPoints, Hero brawler) {
        OfferBundle bundle = new OfferBundle();
        bundle.IsDailyDeals = true;
        bundle.EndTime = truncateToDay(Instant.now()).plus(Duration.ofDays(1)).plus(Duration.ofHours(8));
        Random random = new Random();
        int type = shouldPowerPoints ? 0 : 1;
        switch (type) {
            case 0: {
                int count = random.nextInt(100 - 15) + 15 + 1;
                Offer offer = new Offer(ShopItem.HeroPower, count, brawler.CharacterId);
                bundle.Items.add(offer);
                bundle.Cost = count * 2;
                bundle.Currency = 1;
                break;
            }
            case 1: {
                Offer megaBoxOffer = new Offer(ShopItem.MegaBox, 1);
                bundle.Items.add(megaBoxOffer);
                bundle.Cost = GetShopDiscountedCost(80, random);
                bundle.SetDiscount(80);
                bundle.Currency = 0;
                break;
            }
            default:
                break;
        }
        return bundle;
    }
    public int GetRoboRumbleDifficulty() {
        return GetRoboRumbleDifficulty(null);
    }
    private static int GetHighestSpecialEventDifficulty(int highest, int current,
            Map<Integer, SpecialEventProgress> progressBySlot) {
        int result = Math.max(clamp(highest, 0, 20), clamp(current, 0, 20));
        if (progressBySlot != null) {
            for (SpecialEventProgress progress : progressBySlot.values()) {
                if (progress != null) result = Math.max(result, clamp(progress.Difficulty, 0, 20));
            }
        }
        return result;
    }
    public int GetRoboRumbleHighestDifficulty() {
        synchronized (RoboRumbleProgressGate) {
            RoboRumbleHighestDifficulty = GetHighestSpecialEventDifficulty(
                RoboRumbleHighestDifficulty, RoboRumbleDifficulty, RoboRumbleProgress);
            return RoboRumbleHighestDifficulty;
        }
    }
    public int GetBossFightHighestDifficulty() {
        synchronized (BossFightProgressGate) {
            BossFightHighestDifficulty = GetHighestSpecialEventDifficulty(
                BossFightHighestDifficulty, BossFightDifficulty, BossFightProgress);
            return BossFightHighestDifficulty;
        }
    }
    public int GetTownCrushHighestDifficulty() {
        synchronized (TownCrushProgressGate) {
            TownCrushHighestDifficulty = GetHighestSpecialEventDifficulty(
                TownCrushHighestDifficulty, TownCrushDifficulty, TownCrushProgress);
            return TownCrushHighestDifficulty;
        }
    }
    private static SpecialEventProgress GetSpecialEventProgress(Map<Integer, SpecialEventProgress> progressBySlot,
            EventData eventData, int previousSlot, Instant previousEndTime, int previousDifficulty, int baseDifficulty) {
        if (previousSlot > 0 && previousEndTime != null && previousEndTime.isAfter(Instant.EPOCH)
                && !progressBySlot.containsKey(previousSlot)) {
            SpecialEventProgress previous = new SpecialEventProgress();
            previous.EndTime = previousEndTime;
            previous.Difficulty = clamp(previousDifficulty, 0, 20);
            progressBySlot.put(previousSlot, previous);
        }
        SpecialEventProgress progress = progressBySlot.get(eventData.Slot);
        if (progress == null || !equalsInstant(progress.EndTime, eventData.EndTime)) {
            SpecialEventProgress next = new SpecialEventProgress();
            next.EndTime = eventData.EndTime;
            next.Difficulty = progress == null && previousSlot == eventData.Slot
                && equalsInstant(previousEndTime, eventData.EndTime) ? previousDifficulty : 0;
            if (progress == null || progress.EndTime == null || eventData.EndTime == null
                    || !progress.EndTime.isAfter(eventData.EndTime)) {
                progressBySlot.put(eventData.Slot, next);
            }
            progress = next;
        }
        progress.Difficulty = clamp(Math.max(progress.Difficulty, baseDifficulty), 0, 20);
        return progress;
    }
    private boolean CanCompleteSpecialEvent(EventData eventData, String gameMode,
            Map<Integer, SpecialEventProgress> progressBySlot) {
        if (eventData == null || eventData.EndTime == null || !eventData.EndTime.isAfter(Instant.now())
                || eventData.getLocation() == null || !gameMode.equals(eventData.getLocation().getGameMode())) return false;
        SpecialEventProgress progress = progressBySlot == null ? null : progressBySlot.get(eventData.Slot);
        if (progress != null && progress.EndTime != null && progress.EndTime.isAfter(eventData.EndTime)) return false;
        if (Events != null) {
            for (EventData current : Events) {
                if (current != null && current.Slot == eventData.Slot) {
                    return current.getLocation() != null && gameMode.equals(current.getLocation().getGameMode())
                        && equalsInstant(current.EndTime, eventData.EndTime);
                }
            }
        }
        return true;
    }
    public int GetRoboRumbleDifficulty(EventData eventData) {
        synchronized (RoboRumbleProgressGate) {
            GetRoboRumbleHighestDifficulty();
            if (eventData == null && Events != null) {
                EventData best = null;
                for (EventData e : Events) {
                    if (e == null || e.getLocation() == null || !"RoboRumble".equals(e.getLocation().getGameMode())) continue;
                    if (best == null) { best = e; continue; }
                    boolean eMatch = e.Slot == RoboRumbleEventSlot && e.EndTime != null && e.EndTime.equals(RoboRumbleEventEndTime);
                    boolean bMatch = best.Slot == RoboRumbleEventSlot && best.EndTime != null && best.EndTime.equals(RoboRumbleEventEndTime);
                    if (eMatch != bMatch) {
                        if (eMatch) best = e;
                        continue;
                    }
                    if (e.RoboRumbleDifficulty > best.RoboRumbleDifficulty) best = e;
                }
                eventData = best;
            }
            if (eventData != null) {
                if (RoboRumbleProgress == null) RoboRumbleProgress = new HashMap<>();
                SpecialEventProgress progress = GetSpecialEventProgress(RoboRumbleProgress, eventData,
                    RoboRumbleEventSlot, RoboRumbleEventEndTime, RoboRumbleDifficulty, eventData.RoboRumbleDifficulty);
                RoboRumbleEventSlot = eventData.Slot;
                RoboRumbleEventEndTime = eventData.EndTime;
                RoboRumbleDifficulty = progress.Difficulty;
            }
            RoboRumbleDifficulty = clamp(RoboRumbleDifficulty, 0, 20);
            return RoboRumbleDifficulty;
        }
    }
    public void CompleteRoboRumbleLevel(EventData eventData, int difficulty) {
        synchronized (RoboRumbleProgressGate) {
            if (!CanCompleteSpecialEvent(eventData, "RoboRumble", RoboRumbleProgress)) return;
            int currentDifficulty = GetRoboRumbleDifficulty(eventData);
            RoboRumbleDifficulty = clamp(Math.max(currentDifficulty, clamp(difficulty, 0, 20) + 1), 0, 20);
            RoboRumbleProgress.get(eventData.Slot).Difficulty = RoboRumbleDifficulty;
            GetRoboRumbleHighestDifficulty();
        }
    }
    public int GetBossFightDifficulty() {
        return GetBossFightDifficulty(null);
    }
    public int GetBossFightDifficulty(EventData eventData) {
        synchronized (BossFightProgressGate) {
            GetBossFightHighestDifficulty();
            if (eventData == null && Events != null) {
                EventData best = null;
                for (EventData e : Events) {
                    if (e == null || e.getLocation() == null || !"BossFight".equals(e.getLocation().getGameMode())) continue;
                    if (best == null) { best = e; continue; }
                    boolean eMatch = e.Slot == BossFightEventSlot && e.EndTime != null && e.EndTime.equals(BossFightEventEndTime);
                    boolean bMatch = best.Slot == BossFightEventSlot && best.EndTime != null && best.EndTime.equals(BossFightEventEndTime);
                    if (eMatch != bMatch) {
                        if (eMatch) best = e;
                        continue;
                    }
                    if (e.BossFightDifficulty > best.BossFightDifficulty) best = e;
                }
                eventData = best;
            }
            if (eventData != null) {
                if (BossFightProgress == null) BossFightProgress = new HashMap<>();
                SpecialEventProgress progress = GetSpecialEventProgress(BossFightProgress, eventData,
                    BossFightEventSlot, BossFightEventEndTime, BossFightDifficulty, eventData.BossFightDifficulty);
                BossFightEventSlot = eventData.Slot;
                BossFightEventEndTime = eventData.EndTime;
                BossFightDifficulty = progress.Difficulty;
            }
            BossFightDifficulty = clamp(BossFightDifficulty, 0, 20);
            return BossFightDifficulty;
        }
    }
    public void CompleteBossFightLevel(EventData eventData, int difficulty) {
        synchronized (BossFightProgressGate) {
            if (!CanCompleteSpecialEvent(eventData, "BossFight", BossFightProgress)) return;
            BossFightDifficulty = clamp(Math.max(GetBossFightDifficulty(eventData), clamp(difficulty, 0, 20) + 1), 0, 20);
            BossFightProgress.get(eventData.Slot).Difficulty = BossFightDifficulty;
            GetBossFightHighestDifficulty();
        }
    }
    public int GetTownCrushDifficulty() {
        return GetTownCrushDifficulty(null);
    }
    public int GetTownCrushDifficulty(EventData eventData) {
        synchronized (TownCrushProgressGate) {
            GetTownCrushHighestDifficulty();
            if (eventData == null && Events != null) {
                EventData best = null;
                for (EventData e : Events) {
                    if (e == null || e.getLocation() == null || !"BossFight_TownCrush".equals(e.getLocation().getGameMode())) continue;
                    if (best == null) { best = e; continue; }
                    boolean eMatch = e.Slot == TownCrushEventSlot && e.EndTime != null && e.EndTime.equals(TownCrushEventEndTime);
                    boolean bMatch = best.Slot == TownCrushEventSlot && best.EndTime != null && best.EndTime.equals(TownCrushEventEndTime);
                    if (eMatch != bMatch) {
                        if (eMatch) best = e;
                        continue;
                    }
                    if (e.TownCrushDifficulty > best.TownCrushDifficulty) best = e;
                }
                eventData = best;
            }
            if (eventData != null) {
                if (TownCrushProgress == null) TownCrushProgress = new HashMap<>();
                SpecialEventProgress progress = GetSpecialEventProgress(TownCrushProgress, eventData,
                    TownCrushEventSlot, TownCrushEventEndTime, TownCrushDifficulty, eventData.TownCrushDifficulty);
                TownCrushEventSlot = eventData.Slot;
                TownCrushEventEndTime = eventData.EndTime;
                TownCrushDifficulty = progress.Difficulty;
            }
            TownCrushDifficulty = clamp(TownCrushDifficulty, 0, 20);
            return TownCrushDifficulty;
        }
    }
    public void CompleteTownCrushLevel(EventData eventData, int difficulty) {
        synchronized (TownCrushProgressGate) {
            if (!CanCompleteSpecialEvent(eventData, "BossFight_TownCrush", TownCrushProgress)) return;
            TownCrushDifficulty = clamp(Math.max(GetTownCrushDifficulty(eventData), clamp(difficulty, 0, 20) + 1), 0, 20);
            TownCrushProgress.get(eventData.Slot).Difficulty = TownCrushDifficulty;
            GetTownCrushHighestDifficulty();
        }
    }
    public void LogicDailyData(ByteStream encoder, Instant utcNow) {
        LocalDateTime utc = LocalDateTime.ofInstant(utcNow, ZoneOffset.UTC);
        encoder.WriteVInt(utc.getYear() * 1000 + utc.getDayOfYear());
        encoder.WriteVInt(utc.getHour() * 3600 + utc.getMinute() * 60 + utc.getSecond());
        encoder.WriteVInt(HomeMode.Avatar.GetTrophies());
        encoder.WriteVInt(HomeMode.Avatar.HighestTrophies);
        encoder.WriteVInt(HomeMode.Avatar.HighestTrophies);
        encoder.WriteVInt(TrophyRoadProgress);
        encoder.WriteVInt(Experience + 1909);
        ByteStreamHelper.WriteDataReference(encoder, getThumbnail());
        ByteStreamHelper.WriteDataReference(encoder, NameColorId);
        encoder.WriteVInt(18);
        for (int i = 0; i < 18; i++) {
            encoder.WriteVInt(i);
        }
        encoder.WriteVInt(53);
        for (int i = 0; i < 53; i++) {
            try {
                ByteStreamHelper.WriteDataReference(encoder, GlobalId.CreateGlobalId(29, SelectedSkins[i]));
            } catch (Exception e) {
                ByteStreamHelper.WriteDataReference(encoder, 0);
                SelectedSkins = new int[53];
            }
        }
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(1);
        encoder.WriteVInt(1);
        ByteStreamHelper.WriteDataReference(encoder, GlobalId.CreateGlobalId(29, 29));
        encoder.WriteVInt(UnlockedSkins == null ? 0 : UnlockedSkins.size());
        if (UnlockedSkins != null) {
            for (int s : UnlockedSkins) {
                ByteStreamHelper.WriteDataReference(encoder, s);
            }
        }
        encoder.WriteVInt(UnlockedRankedShopSkins == null ? 0 : UnlockedRankedShopSkins.size());
        if (UnlockedRankedShopSkins != null) {
            for (int skinId : UnlockedRankedShopSkins) {
                ByteStreamHelper.WriteDataReference(encoder, skinId);
            }
        }
        encoder.WriteVInt(1);
        ByteStreamHelper.WriteDataReference(encoder, GlobalId.CreateGlobalId(29, 52));
        encoder.WriteVInt(0);
        encoder.WriteVInt(HomeMode.Avatar.HighestTrophies);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteBoolean(true);
        encoder.WriteVInt(TokenDoublers);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteBoolean(TimedOffer != null);
        if (TimedOffer != null) TimedOffer.Encode(encoder);
        encoder.WriteBoolean(TimedOffer1 != null);
        if (TimedOffer1 != null) TimedOffer1.Encode(encoder);
        encoder.WriteBoolean(false);
        encoder.WriteVInt(2);
        encoder.WriteVInt(2);
        encoder.WriteVInt(2);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(OfferBundles == null ? 0 : OfferBundles.size());
        if (OfferBundles != null) {
            for (OfferBundle offerBundle : OfferBundles) {
                if (offerBundle != null) offerBundle.Encode(encoder, utcNow);
            }
        }
        encoder.WriteVInt(0);
        encoder.WriteVInt(BattleTokens);
        encoder.WriteVInt(GetbattleTokensRefreshSeconds());
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        ByteStreamHelper.WriteDataReference(encoder, getCharacter());
        encoder.WriteString("RU");
        encoder.WriteString(ContentCreator);

        encoder.WriteVInt(11);
        {
            encoder.WriteInt(3);
            encoder.WriteInt(TokenReward);
            encoder.WriteInt(4);
            encoder.WriteInt(TrophiesReward);
            encoder.WriteInt(8);
            encoder.WriteInt(StarPointsGained);
            encoder.WriteInt(7);
            encoder.WriteInt(HomeMode.Avatar.DoNotDisturb ? 1 : 0);
            encoder.WriteInt(9);
            encoder.WriteInt(1);
            encoder.WriteInt(10);
            encoder.WriteInt(PowerPlayTrophiesReward);
            encoder.WriteInt(14);
            encoder.WriteInt(CoinsGained);
            encoder.WriteInt(22);
            encoder.WriteInt(1);
            encoder.WriteInt(15);
            encoder.WriteInt(0);
            encoder.WriteInt(20);
            encoder.WriteInt(DiamondsGained);
            encoder.WriteInt(17);
            encoder.WriteInt(HomeMode.Avatar.DisabledTeamChat ? 1 : 0);
        }
        TokenReward = 0;
        TrophiesReward = 0;
        StarTokenReward = 0;
        StarPointsGained = 0;
        PowerPlayTrophiesReward = 0;
        DiamondsGained = 0;
        EncodeCooldownEntries(encoder, utcNow);
        EncodeBrawlPassSeasons(encoder);
        encoder.WriteVInt(1);
        encoder.WriteVInt(2);
        encoder.WriteVInt(PowerPlayScore);
        if (Quests != null) {
            encoder.WriteBoolean(true);
            Quests.Encode(encoder);
        } else {
            encoder.WriteBoolean(true);
            encoder.WriteVInt(0);
        }
        encoder.WriteBoolean(true);
        Map<Integer, Integer> selectedEmotesByPin = new HashMap<>();
        for (Hero hero : HomeMode.Avatar.Heroes) {
            if (hero == null) continue;
            hero.EnsureSelectedEmotes();
            if (hero.SelectedEmotes == null) continue;
            for (Map.Entry<Integer, Integer> kv : hero.SelectedEmotes.entrySet()) {
                int emoteGlobalId = kv.getValue();
                selectedEmotesByPin.put(emoteGlobalId, kv.getKey());
                EmoteData emoteData = DataTables.Get(DataType.Emote) == null ? null : DataTables.Get(DataType.Emote).GetDataByGlobalId(emoteGlobalId);
                if (emoteData != null && emoteData.getRarityId() == -1 && UnlockedEmotes != null && !UnlockedEmotes.contains(emoteGlobalId)) {
                    UnlockedEmotes.add(emoteGlobalId);
                }
            }
        }
        if (GlobalSelectedEmotes == null) {
            GlobalSelectedEmotes = new HashMap<>();
            GlobalSelectedEmotes.put(4, 0);
            GlobalSelectedEmotes.put(5, 0);
        }
        for (Map.Entry<Integer, Integer> kv : new HashMap<>(GlobalSelectedEmotes).entrySet()) {
            int slot = kv.getKey();
            int emoteGlobalId = kv.getValue();
            if (emoteGlobalId != 0) {
                selectedEmotesByPin.put(emoteGlobalId, slot);
                EmoteData emoteData = DataTables.Get(DataType.Emote) == null ? null : DataTables.Get(DataType.Emote).GetDataByGlobalId(emoteGlobalId);
                if (emoteData != null && UnlockedEmotes != null && !UnlockedEmotes.contains(emoteGlobalId)) {
                    UnlockedEmotes.add(emoteGlobalId);
                }
            }
        }
        if (UnlockedEmotes != null) {
            UnlockedEmotes.removeIf(emoteId -> emoteId == 0);
        }
        List<Integer> emotesToEncode = new ArrayList<>();
        if (UnlockedEmotes != null) {
            for (int id : UnlockedEmotes) {
                EmoteData data = DataTables.Get(DataType.Emote) == null ? null : DataTables.Get(DataType.Emote).GetDataByGlobalId(id);
                if (data != null && !data.IsDefaultBattleEmote) emotesToEncode.add(id);
            }
        }
        if (UnlockedPlayerThumbnails != null) {
            int defThumb = GlobalId.CreateGlobalId(28, 0);
            for (int id : UnlockedPlayerThumbnails) {
                if (id != defThumb) emotesToEncode.add(id);
            }
        }
        encoder.WriteVInt(emotesToEncode.size());
        for (int emoteId : emotesToEncode) {
            ByteStreamHelper.WriteDataReference(encoder, emoteId);
            if (selectedEmotesByPin.containsKey(emoteId)) {
                encoder.WriteVInt(1);
                encoder.WriteVInt(3);
                encoder.WriteVInt(selectedEmotesByPin.get(emoteId));
            } else {
                encoder.WriteVInt(-1);
            }
        }
        encoder.WriteBoolean(true);
        encoder.WriteVInt(4);
        encoder.WriteVInt(SoloLeagueRank);
        encoder.WriteVInt(getSoloLeaguePoints());
        encoder.WriteVInt(TeamLeagueRank);
        encoder.WriteVInt(getTeamLeaguePoints());
        encoder.WriteVInt(SoloHighLeagueRank);
        encoder.WriteVInt(getSoloLeagueHighPoints());
        encoder.WriteVInt(TeamHighLeagueRank);
        encoder.WriteVInt(getTeamLeagueHighPoints());
        encoder.WriteVInt(SoloRankedRewardsUnlocked);
        encoder.WriteVInt(TeamRankedRewardsUnlocked);
        new LogicPlayerRewardData().EncodeBattleEndQuests(encoder, this);
        encoder.WriteInt(0);
    }
    public void LogicConfData(ByteStream encoder, Instant utcNow) {
        encoder.WriteVInt(0);
        encoder.WriteVInt(25);
        for (int i = 1; i <= 25; i++) encoder.WriteVInt(i);
        int eventCount = Events == null ? 0 : Events.length;
        encoder.WriteVInt(eventCount);
        if (Events != null) {
            for (EventData data : Events) {
                if (data == null) continue;
                data.IsSecondary = data.IsEarlyAccess;
                data.Encode(encoder, this);
            }
        }
        encoder.WriteVInt(eventCount);
        if (Events != null) {
            for (EventData data : Events) {
                if (data == null) continue;
                data.IsSecondary = true;
                if (data.EndTime != null) data.EndTime.plusSeconds((int) Duration.between(Instant.now(), data.EndTime).getSeconds());
                data.Encode(encoder, this);
            }
        }
        encoder.WriteVInt(8);
        encoder.WriteVInt(20);
        encoder.WriteVInt(35);
        encoder.WriteVInt(75);
        encoder.WriteVInt(140);
        encoder.WriteVInt(290);
        encoder.WriteVInt(480);
        encoder.WriteVInt(800);
        encoder.WriteVInt(1250);
        ByteStreamHelper.WriteIntList(encoder, toIntegerList(GoldPacksPrice));
        ByteStreamHelper.WriteIntList(encoder, toIntegerList(GoldPacksAmount));
        encoder.WriteBoolean(true);
        encoder.WriteVInt(1);
        ByteStreamHelper.WriteDataReference(encoder, 16000047);
        Instant releaseTime = LocalDateTime.of(2026, 8, 3, 8, 0, 0).toInstant(ZoneOffset.UTC);
        encoder.WriteInt((int) Duration.between(Instant.now(), releaseTime).getSeconds());
        encoder.WriteInt((int) Duration.between(Instant.now(), releaseTime).getSeconds());
        boolean shouldShowRegularQuestPreview = TrophyRoadProgress >= 11;
        List<Integer> logicConfData = new ArrayList<>(List.of(1, 41000028, 10019, BattleReplayConfig.Enabled ? 1 : 0, 10022, BattleReplayConfig.RetentionSeconds, 47, GetSecondsUntilNextQuestRefresh(utcNow), 48, GetSecondsUntilNextRegularQuestRefresh(utcNow), 50, shouldShowRegularQuestPreview ? UPCOMING_REGULAR_QUEST_PREVIEW.length : 0));
        SkinOffersFile skinFile = LoadSkinOffersFile();
        int skinSectionId = ApplySkinOfferConf(logicConfData, skinFile, utcNow);
        boolean hasSlot20 = false;
        if (Events != null) {
            for (EventData e : Events) {
                if (e != null && e.Slot == 20 && e.EndTime != null && e.EndTime.isAfter(utcNow)) { hasSlot20 = true; break; }
            }
        }
        if (hasSlot20) {
            for (int i = 0; i + 1 < logicConfData.size(); i += 2) {
                if (logicConfData.get(i) != 36) continue;
                logicConfData.set(i + 1, 0);
                break;
            }
        }
        if (shouldShowRegularQuestPreview) {
            for (int i = 0; i < UPCOMING_REGULAR_QUEST_PREVIEW.length; i++) {
                logicConfData.add(1000 + i);
                logicConfData.add(UPCOMING_REGULAR_QUEST_PREVIEW[i].IsPremium ? 1 : 0);
                logicConfData.add(1100 + i);
                logicConfData.add(UPCOMING_REGULAR_QUEST_PREVIEW[i].Reward);
            }
        }
        encoder.WriteVInt(logicConfData.size() / 2);
        for (int i = 0; i < logicConfData.size() / 2; i++) {
            encoder.WriteInt(logicConfData.get(i * 2));
            encoder.WriteInt(logicConfData.get(i * 2 + 1));
        }
        encoder.WriteVInt(skinSectionId > 0 ? 2 : 1);
        encoder.WriteVInt(14);
        encoder.WriteVInt(1);
        encoder.WriteVInt(0);
        encoder.WriteVInt(739760);
        if (skinSectionId > 0) {
            encoder.WriteVInt(29);
            encoder.WriteVInt(skinSectionId);
            encoder.WriteVInt(0);
            encoder.WriteVInt((int)Math.min(Integer.MAX_VALUE, Math.max(0, Duration.between(utcNow, skinFile.EndTime).getSeconds())));
        }
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
    }
    private void EncodeCooldownEntries(ByteStream encoder, Instant utcNow) {
        int rankedCooldownSeconds = GetRankedDraftCooldownRemainingSeconds(utcNow);
        int cooldownCount = rankedCooldownSeconds > 0 ? 1 : 0;
        encoder.WriteVInt(cooldownCount);
        if (rankedCooldownSeconds <= 0) return;
        encoder.WriteVInt(2);
        ByteStreamHelper.WriteDataReference((ChecksumEncoder) encoder, 0);
        encoder.WriteVInt(rankedCooldownSeconds);
    }
    public void Encode(ByteStream encoder) {
        Instant utcNow = Instant.now();
        EnsureRankedSeasonProgress().ProcessCompletedRewards(this);
        Notification pendingRankedRewardNotification = EnsureRankedSeasonProgress().CreatePendingRewardNotification(this);
        if (pendingRankedRewardNotification != null) {
            if (NotificationFactory == null) NotificationFactory = new NotificationFactory();
            NotificationFactory.Add(pendingRankedRewardNotification);
        }
        LogicDailyData(encoder, utcNow);
        LogicConfData(encoder, utcNow);
        encoder.WriteLong(HomeId);
        NotificationFactory.Encode(encoder, ShowWelcomePopup);
        ShowWelcomePopup = false;
        encoder.WriteVInt(0);
        encoder.WriteVInt(0);
        encoder.WriteBoolean(false);
        encoder.WriteVInt(0);
    }
    private static Instant truncateToDay(Instant v) {
        if (v == null) return null;
        return v.truncatedTo(ChronoUnit.DAYS);
    }
    private static int yearOf(Instant v) {
        return LocalDateTime.ofInstant(v, ZoneOffset.UTC).getYear();
    }
    private static boolean equalsInstant(Instant a, Instant b) {
        if (a == null && b == null) return true;
        if (a == null || b == null) return false;
        return a.equals(b);
    }
    private static List<Integer> toIntegerList(int[] arr) {
        List<Integer> list = new ArrayList<>(arr.length);
        for (int v : arr) list.add(v);
        return list;
    }
}
