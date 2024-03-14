// This file is generated by "defs2struct.py".
// Please do not edit.

#ifndef LEXICONS_H
#define LEXICONS_H

#include <QList>
#include <QSharedPointer>
#include <QString>
#include <QVariant>

namespace AtProtocolType {
struct Blob
{
    QString cid;
    QString mimeType;
    QString alt;
    int size = 0;
};
enum ThreadGateType : int {
    Everybody,
    Nobody,
    Choice,
};
enum ThreadGateAllowType : int {
    Mentioned,
    Followed,
    List,
};
struct ThreadGateAllow
{
    ThreadGateAllowType type = ThreadGateAllowType::Mentioned;
    QString uri;
};

namespace AppBskyActorDefs {
struct ProfileView;
}
namespace AppBskyEmbedRecord {
struct Main;
struct View;
}
namespace AppBskyFeedDefs {
struct ThreadViewPost;
}
namespace AppBskyRichtextFacet {
struct Main;
}

// com.atproto.label.defs
namespace ComAtprotoLabelDefs {
struct Label
{
    int ver = 0; // The AT Protocol version of the label object.
    QString src; // did , DID of the actor who created this label.
    QString uri; // uri , AT URI of the record, repository (account), or other resource that this
                 // label applies to.
    QString cid; // cid , Optionally, CID specifying the specific version of 'uri' resource this
                 // label applies to.
    QString val; // The short string name of the value or type of this label.
    bool neg = false; // If true, this is a negation label, overwriting a previous label.
    QString cts; // datetime , Timestamp when this label was created.
    QString exp; // datetime , Timestamp at which this label expires (no longer applies).
};
struct SelfLabel
{
    QString val; // The short string name of the value or type of this label.
};
struct SelfLabels
{
    QList<SelfLabel> values;
};
typedef QString LabelValue;
struct LabelValueDefinitionStrings
{
    QString lang; // language , The code of the language these strings are written in.
    QString name; // A short human-readable name for the label.
    QString description; // A longer description of what the label means and why it might be
                         // applied.
};
struct LabelValueDefinition
{
    QString identifier; // The value of the label being defined. Must only include lowercase ascii
                        // and the '-' character ([a-z-]+).
    QString severity; // How should a client visually convey this label? 'inform' means neutral and
                      // informational; 'alert' means negative and warning; 'none' means show
                      // nothing.
    QString blurs; // What should this label hide in the UI, if applied? 'content' hides all of the
                   // target; 'media' hides the images/video/audio; 'none' hides nothing.
    QString defaultSetting; // The default setting for this label.
    bool adultOnly = false; // Does the user need to have adult content enabled in order to
                            // configure this label?
    QList<LabelValueDefinitionStrings> locales;
};
}

// app.bsky.graph.defs
namespace AppBskyGraphDefs {
typedef QString ListPurpose;
struct ListViewerState
{
    bool muted = false;
    QString blocked; // at-uri
};
struct ListViewBasic
{
    QString uri; // at-uri
    QString cid; // cid
    QString name;
    ListPurpose purpose;
    QString avatar;
    QList<ComAtprotoLabelDefs::Label> labels;
    ListViewerState viewer;
    QString indexedAt; // datetime
};
struct ListView
{
    QString uri; // at-uri
    QString cid; // cid
    QSharedPointer<AppBskyActorDefs::ProfileView> creator;
    QString name;
    ListPurpose purpose;
    QString description;
    QList<QSharedPointer<AppBskyRichtextFacet::Main>> descriptionFacets;
    QString avatar;
    QList<ComAtprotoLabelDefs::Label> labels;
    ListViewerState viewer;
    QString indexedAt; // datetime
};
struct ListItemView
{
    QString uri; // at-uri
    QSharedPointer<AppBskyActorDefs::ProfileView> subject;
};
struct NotFoundActor
{
    QString actor; // at-identifier
    bool notFound = false;
};
struct Relationship
{
    QString did; // did
    QString following; // at-uri , if the actor follows this DID, this is the AT-URI of the follow
                       // record
    QString followedBy; // at-uri , if the actor is followed by this DID, contains the AT-URI of the
                        // follow record
};
}

// app.bsky.actor.defs
namespace AppBskyActorDefs {
struct ViewerState
{
    bool muted = false;
    AppBskyGraphDefs::ListViewBasic mutedByList;
    bool blockedBy = false;
    QString blocking; // at-uri
    AppBskyGraphDefs::ListViewBasic blockingByList;
    QString following; // at-uri
    QString followedBy; // at-uri
};
struct ProfileViewBasic
{
    QString did; // did
    QString handle; // handle
    QString displayName;
    QString avatar;
    ViewerState viewer;
    QList<ComAtprotoLabelDefs::Label> labels;
};
struct ProfileView
{
    QString did; // did
    QString handle; // handle
    QString displayName;
    QString description;
    QString avatar;
    QString indexedAt; // datetime
    ViewerState viewer;
    QList<ComAtprotoLabelDefs::Label> labels;
};
struct ProfileAssociated
{
    int lists = 0;
    int feedgens = 0;
    bool labeler = false;
};
struct ProfileViewDetailed
{
    QString did; // did
    QString handle; // handle
    QString displayName;
    QString description;
    QString avatar;
    QString banner;
    int followersCount = 0;
    int followsCount = 0;
    int postsCount = 0;
    ProfileAssociated associated;
    QString indexedAt; // datetime
    ViewerState viewer;
    QList<ComAtprotoLabelDefs::Label> labels;
};
struct AdultContentPref
{
    bool enabled = false;
};
struct ContentLabelPref
{
    QString labelerDid; // did , Which labeler does this preference apply to? If undefined, applies
                        // globally.
    QString label;
    QString visibility;
};
struct SavedFeedsPref
{
    QList<QString> pinned;
    QList<QString> saved;
    int timelineIndex = 0;
};
struct PersonalDetailsPref
{
    QString birthDate; // datetime , The birth date of account owner.
};
struct FeedViewPref
{
    QString feed; // The URI of the feed, or an identifier which describes the feed.
    bool hideReplies = false; // Hide replies in the feed.
    bool hideRepliesByUnfollowed =
            false; // Hide replies in the feed if they are not by followed users.
    int hideRepliesByLikeCount =
            0; // Hide replies in the feed if they do not have this number of likes.
    bool hideReposts = false; // Hide reposts in the feed.
    bool hideQuotePosts = false; // Hide quote posts in the feed.
};
struct ThreadViewPref
{
    QString sort; // Sorting mode for threads.
    bool prioritizeFollowedUsers = false; // Show followed users at the top of all replies.
};
struct InterestsPref
{
    QList<QString> tags; // A list of tags which describe the account owner's interests gathered
                         // during onboarding.
};
typedef QString MutedWordTarget;
struct MutedWord
{
    QString value; // The muted word itself.
    QList<AppBskyActorDefs::MutedWordTarget> targets;
};
struct MutedWordsPref
{
    QList<AppBskyActorDefs::MutedWord> items;
};
struct HiddenPostsPref
{
    QList<QString> items; // A list of URIs of posts the account owner has hidden.
};
struct LabelerPrefItem
{
    QString did; // did
};
struct LabelersPref
{
    QList<LabelerPrefItem> labelers;
};
}

// app.bsky.actor.profile
namespace AppBskyActorProfile {
enum class MainLabelsType : int {
    none,
    labels_ComAtprotoLabelDefs_SelfLabels,
};
struct Main
{
    QString displayName;
    QString description; // Free-form profile description text.
    Blob avatar; // Small image to be displayed next to posts from account. AKA, 'profile picture'
    Blob banner; // Larger horizontal image to display behind profile view.
    // union start : labels
    MainLabelsType labels_type = MainLabelsType::none;
    ComAtprotoLabelDefs::SelfLabels
            labels_ComAtprotoLabelDefs_SelfLabels; // Self-label values, specific to the Bluesky
                                                   // application, on the overall account.
    // union end : labels
};
}

// app.bsky.embed.external
namespace AppBskyEmbedExternal {
struct External
{
    QString uri; // uri
    QString title;
    QString description;
    Blob thumb;
};
struct Main
{
    External external;
};
struct ViewExternal
{
    QString uri; // uri
    QString title;
    QString description;
    QString thumb;
};
struct View
{
    ViewExternal external;
};
}

// app.bsky.embed.images
namespace AppBskyEmbedImages {
// A set of images embedded in a Bluesky record (eg, a post).
struct AspectRatio
{
    int width = 0;
    int height = 0;
};
struct Image
{
    Blob image;
    QString alt; // Alt text description of the image, for accessibility.
    AspectRatio aspectRatio;
};
struct Main
{
    QList<Image> images;
};
struct ViewImage
{
    QString thumb; // Fully-qualified URL where a thumbnail of the image can be fetched. For
                   // example, CDN location provided by the App View.
    QString fullsize; // Fully-qualified URL where a large version of the image can be fetched. May
                      // or may not be the exact original blob. For example, CDN location provided
                      // by the App View.
    QString alt; // Alt text description of the image, for accessibility.
    AspectRatio aspectRatio;
};
struct View
{
    QList<ViewImage> images;
};
}

// com.atproto.repo.strongRef
namespace ComAtprotoRepoStrongRef {
struct Main
{
    QString uri; // at-uri
    QString cid; // cid
};
// A URI with a content-hash fingerprint.
}

// app.bsky.embed.recordWithMedia
namespace AppBskyEmbedRecordWithMedia {
enum class MainMediaType : int {
    none,
    media_AppBskyEmbedImages_Main,
    media_AppBskyEmbedExternal_Main,
};
enum class ViewMediaType : int {
    none,
    media_AppBskyEmbedImages_View,
    media_AppBskyEmbedExternal_View,
};
struct View
{
    QSharedPointer<AppBskyEmbedRecord::View> record;
    // union start : media
    ViewMediaType media_type = ViewMediaType::none;
    AppBskyEmbedImages::View media_AppBskyEmbedImages_View;
    AppBskyEmbedExternal::View media_AppBskyEmbedExternal_View;
    // union end : media
};
// A representation of a record embedded in a Bluesky record (eg, a post), alongside other
// compatible embeds. For example, a quote post and image, or a quote post and external URL card.
struct Main
{
    QSharedPointer<AppBskyEmbedRecord::Main> record;
    // union start : media
    MainMediaType media_type = MainMediaType::none;
    AppBskyEmbedImages::Main media_AppBskyEmbedImages_Main;
    AppBskyEmbedExternal::Main media_AppBskyEmbedExternal_Main;
    // union end : media
};
}

// app.bsky.richtext.facet
namespace AppBskyRichtextFacet {
enum class MainFeaturesType : int {
    none,
    features_Mention,
    features_Link,
    features_Tag,
};
struct ByteSlice
{
    int byteStart = 0;
    int byteEnd = 0;
};
struct Mention
{
    QString did; // did
};
struct Link
{
    QString uri; // uri
};
struct Tag
{
    QString tag;
};
struct Main
{
    ByteSlice index;
    // union start : features
    MainFeaturesType features_type = MainFeaturesType::none;
    QList<Mention> features_Mention;
    QList<Link> features_Link;
    QList<Tag> features_Tag;
    // union end : features
};
}

// app.bsky.feed.defs
namespace AppBskyFeedDefs {
enum class SkeletonFeedPostReasonType : int {
    none,
    reason_SkeletonReasonRepost,
};
enum class ThreadViewPostParentType : int {
    none,
    parent_ThreadViewPost,
    parent_NotFoundPost,
    parent_BlockedPost,
};
enum class ThreadViewPostRepliesType : int {
    none,
    replies_ThreadViewPost,
    replies_NotFoundPost,
    replies_BlockedPost,
};
enum class FeedViewPostReasonType : int {
    none,
    reason_ReasonRepost,
};
enum class ReplyRefRootType : int {
    none,
    root_PostView,
    root_NotFoundPost,
    root_BlockedPost,
};
enum class ReplyRefParentType : int {
    none,
    parent_PostView,
    parent_NotFoundPost,
    parent_BlockedPost,
};
enum class PostViewEmbedType : int {
    none,
    embed_AppBskyEmbedImages_View,
    embed_AppBskyEmbedExternal_View,
    embed_AppBskyEmbedRecord_View,
    embed_AppBskyEmbedRecordWithMedia_View,
};
struct BlockedAuthor
{
    QString did; // did
    AppBskyActorDefs::ViewerState viewer;
};
struct GeneratorViewerState
{
    QString like; // at-uri
};
struct GeneratorView
{
    QString uri; // at-uri
    QString cid; // cid
    QString did; // did
    AppBskyActorDefs::ProfileView creator;
    QString displayName;
    QString description;
    QList<AppBskyRichtextFacet::Main> descriptionFacets;
    QString avatar;
    int likeCount = 0;
    QList<ComAtprotoLabelDefs::Label> labels;
    GeneratorViewerState viewer;
    QString indexedAt; // datetime
};
struct ViewerState
{
    QString repost; // at-uri
    QString like; // at-uri
    bool replyDisabled = false;
};
struct ThreadgateView
{
    QString uri; // at-uri
    QString cid; // cid
    QVariant record;
    QList<AppBskyGraphDefs::ListViewBasic> lists;
};
struct PostView
{
    QString uri; // at-uri
    QString cid; // cid
    AppBskyActorDefs::ProfileViewBasic author;
    QVariant record;
    // union start : embed
    PostViewEmbedType embed_type = PostViewEmbedType::none;
    AppBskyEmbedImages::View embed_AppBskyEmbedImages_View;
    AppBskyEmbedExternal::View embed_AppBskyEmbedExternal_View;
    QSharedPointer<AppBskyEmbedRecord::View> embed_AppBskyEmbedRecord_View;
    AppBskyEmbedRecordWithMedia::View embed_AppBskyEmbedRecordWithMedia_View;
    // union end : embed
    int replyCount = 0;
    int repostCount = 0;
    int likeCount = 0;
    QString indexedAt; // datetime
    ViewerState viewer;
    QList<ComAtprotoLabelDefs::Label> labels;
    ThreadgateView threadgate;
};
struct NotFoundPost
{
    QString uri; // at-uri
    bool notFound = false;
};
struct BlockedPost
{
    QString uri; // at-uri
    bool blocked = false;
    BlockedAuthor author;
};
struct ReplyRef
{
    // union start : root
    ReplyRefRootType root_type = ReplyRefRootType::none;
    PostView root_PostView;
    NotFoundPost root_NotFoundPost;
    BlockedPost root_BlockedPost;
    // union end : root
    // union start : parent
    ReplyRefParentType parent_type = ReplyRefParentType::none;
    PostView parent_PostView;
    NotFoundPost parent_NotFoundPost;
    BlockedPost parent_BlockedPost;
    // union end : parent
};
struct ReasonRepost
{
    AppBskyActorDefs::ProfileViewBasic by;
    QString indexedAt; // datetime
};
struct FeedViewPost
{
    PostView post;
    ReplyRef reply;
    // union start : reason
    FeedViewPostReasonType reason_type = FeedViewPostReasonType::none;
    ReasonRepost reason_ReasonRepost;
    // union end : reason
};
struct ThreadViewPost
{
    PostView post;
    // union start : parent
    ThreadViewPostParentType parent_type = ThreadViewPostParentType::none;
    QSharedPointer<ThreadViewPost> parent_ThreadViewPost;
    NotFoundPost parent_NotFoundPost;
    BlockedPost parent_BlockedPost;
    // union end : parent
    // union start : replies
    ThreadViewPostRepliesType replies_type = ThreadViewPostRepliesType::none;
    QList<QSharedPointer<ThreadViewPost>> replies_ThreadViewPost;
    QList<NotFoundPost> replies_NotFoundPost;
    QList<BlockedPost> replies_BlockedPost;
    // union end : replies
};
struct SkeletonReasonRepost
{
    QString repost; // at-uri
};
struct SkeletonFeedPost
{
    QString post; // at-uri
    // union start : reason
    SkeletonFeedPostReasonType reason_type = SkeletonFeedPostReasonType::none;
    SkeletonReasonRepost reason_SkeletonReasonRepost;
    // union end : reason
};
}

// app.bsky.labeler.defs
namespace AppBskyLabelerDefs {
struct LabelerViewerState
{
    QString like; // at-uri
};
struct LabelerView
{
    QString uri; // at-uri
    QString cid; // cid
    AppBskyActorDefs::ProfileView creator;
    int likeCount = 0;
    LabelerViewerState viewer;
    QString indexedAt; // datetime
    QList<ComAtprotoLabelDefs::Label> labels;
};
struct LabelerPolicies
{
    QList<ComAtprotoLabelDefs::LabelValue> labelValues;
    QList<ComAtprotoLabelDefs::LabelValueDefinition> labelValueDefinitions;
};
struct LabelerViewDetailed
{
    QString uri; // at-uri
    QString cid; // cid
    AppBskyActorDefs::ProfileView creator;
    AppBskyLabelerDefs::LabelerPolicies policies;
    int likeCount = 0;
    LabelerViewerState viewer;
    QString indexedAt; // datetime
    QList<ComAtprotoLabelDefs::Label> labels;
};
}

// app.bsky.embed.record
namespace AppBskyEmbedRecord {
enum class ViewRecordType : int {
    none,
    record_ViewRecord,
    record_ViewNotFound,
    record_ViewBlocked,
    record_AppBskyFeedDefs_GeneratorView,
    record_AppBskyGraphDefs_ListView,
    record_AppBskyLabelerDefs_LabelerView,
};
enum class ViewRecordEmbedsType : int {
    none,
    embeds_AppBskyEmbedImages_View,
    embeds_AppBskyEmbedExternal_View,
    embeds_AppBskyEmbedRecord_View,
    embeds_AppBskyEmbedRecordWithMedia_View,
};
// A representation of a record embedded in a Bluesky record (eg, a post). For example, a
// quote-post, or sharing a feed generator record.
struct Main
{
    ComAtprotoRepoStrongRef::Main record;
};
struct ViewRecord
{
    QString uri; // at-uri
    QString cid; // cid
    AppBskyActorDefs::ProfileViewBasic author;
    QVariant value; // The record data itself.
    QList<ComAtprotoLabelDefs::Label> labels;
    // union start : embeds
    ViewRecordEmbedsType embeds_type = ViewRecordEmbedsType::none;
    QList<AppBskyEmbedImages::View> embeds_AppBskyEmbedImages_View;
    QList<AppBskyEmbedExternal::View> embeds_AppBskyEmbedExternal_View;
    QList<QSharedPointer<AppBskyEmbedRecord::View>> embeds_AppBskyEmbedRecord_View;
    QList<AppBskyEmbedRecordWithMedia::View> embeds_AppBskyEmbedRecordWithMedia_View;
    // union end : embeds
    QString indexedAt; // datetime
};
struct ViewNotFound
{
    QString uri; // at-uri
    bool notFound = false;
};
struct ViewBlocked
{
    QString uri; // at-uri
    bool blocked = false;
    AppBskyFeedDefs::BlockedAuthor author;
};
struct View
{
    // union start : record
    ViewRecordType record_type = ViewRecordType::none;
    ViewRecord record_ViewRecord;
    ViewNotFound record_ViewNotFound;
    ViewBlocked record_ViewBlocked;
    AppBskyFeedDefs::GeneratorView record_AppBskyFeedDefs_GeneratorView;
    AppBskyGraphDefs::ListView record_AppBskyGraphDefs_ListView;
    AppBskyLabelerDefs::LabelerView record_AppBskyLabelerDefs_LabelerView;
    // union end : record
};
}

// app.bsky.feed.describeFeedGenerator
namespace AppBskyFeedDescribeFeedGenerator {
struct Feed
{
    QString uri; // at-uri
};
struct Links
{
    QString privacyPolicy;
    QString termsOfService;
};
}

// app.bsky.feed.generator
namespace AppBskyFeedGenerator {
enum class MainLabelsType : int {
    none,
    labels_ComAtprotoLabelDefs_SelfLabels,
};
struct Main
{
    QString did; // did
    QString displayName;
    QString description;
    QList<AppBskyRichtextFacet::Main> descriptionFacets;
    Blob avatar;
    // union start : labels
    MainLabelsType labels_type = MainLabelsType::none;
    ComAtprotoLabelDefs::SelfLabels labels_ComAtprotoLabelDefs_SelfLabels; // Self-label values
    // union end : labels
    QString createdAt; // datetime
};
}

// app.bsky.feed.getLikes
namespace AppBskyFeedGetLikes {
struct Like
{
    QString indexedAt; // datetime
    QString createdAt; // datetime
    AppBskyActorDefs::ProfileView actor;
};
}

// app.bsky.feed.like
namespace AppBskyFeedLike {
struct Main
{
    ComAtprotoRepoStrongRef::Main subject;
    QString createdAt; // datetime
};
}

// app.bsky.feed.post
namespace AppBskyFeedPost {
enum class MainEmbedType : int {
    none,
    embed_AppBskyEmbedImages_Main,
    embed_AppBskyEmbedExternal_Main,
    embed_AppBskyEmbedRecord_Main,
    embed_AppBskyEmbedRecordWithMedia_Main,
};
enum class MainLabelsType : int {
    none,
    labels_ComAtprotoLabelDefs_SelfLabels,
};
struct TextSlice
{
    int start = 0;
    int end = 0;
};
struct Entity
{
    TextSlice index;
    QString type; // Expected values are 'mention' and 'link'.
    QString value;
};
struct ReplyRef
{
    ComAtprotoRepoStrongRef::Main root;
    ComAtprotoRepoStrongRef::Main parent;
};
struct Main
{
    QString text; // The primary post content. May be an empty string, if there are embeds.
    QList<AppBskyRichtextFacet::Main> facets;
    ReplyRef reply;
    // union start : embed
    MainEmbedType embed_type = MainEmbedType::none;
    AppBskyEmbedImages::Main embed_AppBskyEmbedImages_Main;
    AppBskyEmbedExternal::Main embed_AppBskyEmbedExternal_Main;
    AppBskyEmbedRecord::Main embed_AppBskyEmbedRecord_Main;
    AppBskyEmbedRecordWithMedia::Main embed_AppBskyEmbedRecordWithMedia_Main;
    // union end : embed
    QList<QString> langs; // Indicates human language of post primary text content.
    // union start : labels
    MainLabelsType labels_type = MainLabelsType::none;
    ComAtprotoLabelDefs::SelfLabels
            labels_ComAtprotoLabelDefs_SelfLabels; // Self-label values for this post. Effectively
                                                   // content warnings.
    // union end : labels
    QList<QString>
            tags; // Additional hashtags, in addition to any included in post text and facets.
    QString createdAt; // datetime , Client-declared timestamp when this post was originally
                       // created.
    QString via; // client name(Unofficial field)
};
}

// app.bsky.feed.repost
namespace AppBskyFeedRepost {
struct Main
{
    ComAtprotoRepoStrongRef::Main subject;
    QString createdAt; // datetime
};
}

// app.bsky.feed.threadgate
namespace AppBskyFeedThreadgate {
enum class MainAllowType : int {
    none,
    allow_MentionRule,
    allow_FollowingRule,
    allow_ListRule,
};
struct MentionRule
{
};
struct FollowingRule
{
};
struct ListRule
{
    QString list; // at-uri
};
struct Main
{
    QString post; // at-uri , Reference (AT-URI) to the post record.
    // union start : allow
    MainAllowType allow_type = MainAllowType::none;
    QList<MentionRule> allow_MentionRule;
    QList<FollowingRule> allow_FollowingRule;
    QList<ListRule> allow_ListRule;
    // union end : allow
    QString createdAt; // datetime
};
}

// app.bsky.graph.block
namespace AppBskyGraphBlock {
struct Main
{
    QString subject; // did , DID of the account to be blocked.
    QString createdAt; // datetime
};
}

// app.bsky.graph.follow
namespace AppBskyGraphFollow {
struct Main
{
    QString subject; // did
    QString createdAt; // datetime
};
}

// app.bsky.graph.list
namespace AppBskyGraphList {
enum class MainLabelsType : int {
    none,
    labels_ComAtprotoLabelDefs_SelfLabels,
};
struct Main
{
    AppBskyGraphDefs::ListPurpose purpose;
    QString name; // Display name for list; can not be empty.
    QString description;
    QList<AppBskyRichtextFacet::Main> descriptionFacets;
    Blob avatar;
    // union start : labels
    MainLabelsType labels_type = MainLabelsType::none;
    ComAtprotoLabelDefs::SelfLabels labels_ComAtprotoLabelDefs_SelfLabels;
    // union end : labels
    QString createdAt; // datetime
};
}

// app.bsky.graph.listblock
namespace AppBskyGraphListblock {
struct Main
{
    QString subject; // at-uri , Reference (AT-URI) to the mod list record.
    QString createdAt; // datetime
};
}

// app.bsky.graph.listitem
namespace AppBskyGraphListitem {
struct Main
{
    QString subject; // did , The account which is included on the list.
    QString list; // at-uri , Reference (AT-URI) to the list record (app.bsky.graph.list).
    QString createdAt; // datetime
};
}

// app.bsky.labeler.service
namespace AppBskyLabelerService {
enum class MainLabelsType : int {
    none,
    labels_ComAtprotoLabelDefs_SelfLabels,
};
struct Main
{
    AppBskyLabelerDefs::LabelerPolicies policies;
    // union start : labels
    MainLabelsType labels_type = MainLabelsType::none;
    ComAtprotoLabelDefs::SelfLabels labels_ComAtprotoLabelDefs_SelfLabels;
    // union end : labels
    QString createdAt; // datetime
};
}

// app.bsky.notification.listNotifications
namespace AppBskyNotificationListNotifications {
struct Notification
{
    QString uri; // at-uri
    QString cid; // cid
    AppBskyActorDefs::ProfileView author;
    QString reason; // Expected values are 'like', 'repost', 'follow', 'mention', 'reply', and
                    // 'quote'.
    QString reasonSubject; // at-uri
    QVariant record;
    bool isRead = false;
    QString indexedAt; // datetime
    QList<ComAtprotoLabelDefs::Label> labels;
};
}

// app.bsky.unspecced.defs
namespace AppBskyUnspeccedDefs {
struct SkeletonSearchPost
{
    QString uri; // at-uri
};
struct SkeletonSearchActor
{
    QString did; // did
};
}

// app.bsky.unspecced.getTaggedSuggestions
namespace AppBskyUnspeccedGetTaggedSuggestions {
struct Suggestion
{
    QString tag;
    QString subjectType;
    QString subject; // uri
};
}

// com.atproto.server.defs
namespace ComAtprotoServerDefs {
struct InviteCodeUse
{
    QString usedBy; // did
    QString usedAt; // datetime
};
struct InviteCode
{
    QString code;
    int available = 0;
    bool disabled = false;
    QString forAccount;
    QString createdBy;
    QString createdAt; // datetime
    QList<InviteCodeUse> uses;
};
}

// com.atproto.admin.defs
namespace ComAtprotoAdminDefs {
struct StatusAttr
{
    bool applied = false;
    QString ref;
};
struct AccountView
{
    QString did; // did
    QString handle; // handle
    QString email;
    QString indexedAt; // datetime
    ComAtprotoServerDefs::InviteCode invitedBy;
    QList<ComAtprotoServerDefs::InviteCode> invites;
    bool invitesDisabled = false;
    QString emailConfirmedAt; // datetime
    QString inviteNote;
};
struct RepoRef
{
    QString did; // did
};
struct RepoBlobRef
{
    QString did; // did
    QString cid; // cid
    QString recordUri; // at-uri
};
}

// com.atproto.label.subscribeLabels
namespace ComAtprotoLabelSubscribeLabels {
struct Labels
{
    int seq = 0;
    QList<ComAtprotoLabelDefs::Label> labels;
};
struct Info
{
    QString name;
    QString message;
};
}

// com.atproto.moderation.defs
namespace ComAtprotoModerationDefs {
typedef QString ReasonType;
}

// com.atproto.repo.applyWrites
namespace ComAtprotoRepoApplyWrites {
struct Create
{
    QString collection; // nsid
    QString rkey;
    QVariant value;
};
struct Update
{
    QString collection; // nsid
    QString rkey;
    QVariant value;
};
struct Delete
{
    QString collection; // nsid
    QString rkey;
};
}

// com.atproto.repo.listMissingBlobs
namespace ComAtprotoRepoListMissingBlobs {
struct RecordBlob
{
    QString cid; // cid
    QString recordUri; // at-uri
};
}

// com.atproto.repo.listRecords
namespace ComAtprotoRepoListRecords {
struct Record
{
    QString uri; // at-uri
    QString cid; // cid
    QVariant value;
};
}

// com.atproto.server.createAppPassword
namespace ComAtprotoServerCreateAppPassword {
struct AppPassword
{
    QString name;
    QString password;
    QString createdAt; // datetime
};
}

// com.atproto.server.createInviteCodes
namespace ComAtprotoServerCreateInviteCodes {
struct AccountCodes
{
    QString account;
    QList<QString> codes;
};
}

// com.atproto.server.describeServer
namespace ComAtprotoServerDescribeServer {
struct Links
{
    QString privacyPolicy;
    QString termsOfService;
};
struct Contact
{
    QString email;
};
}

// com.atproto.server.listAppPasswords
namespace ComAtprotoServerListAppPasswords {
struct AppPassword
{
    QString name;
    QString createdAt; // datetime
};
}

// com.atproto.sync.listRepos
namespace ComAtprotoSyncListRepos {
struct Repo
{
    QString did; // did
    QString head; // cid , Current repo commit CID
    QString rev;
};
}

// com.atproto.sync.subscribeRepos
namespace ComAtprotoSyncSubscribeRepos {
struct RepoOp
{
    QString action;
    QString path;
};
struct Commit
{
    int seq = 0; // The stream sequence number of this message.
    bool tooBig =
            false; // Indicates that this commit contained too many ops, or data size was too large.
                   // Consumers will need to make a separate request to get missing data.
    QString repo; // did , The repo this event comes from.
    QString rev; // The rev of the emitted commit. Note that this information is also in the commit
                 // object included in blocks, unless this is a tooBig event.
    QString since; // The rev of the last emitted commit from this repo (if any).
    QList<RepoOp> ops;
    QString time; // datetime , Timestamp of when this message was originally broadcast.
};
struct Identity
{
    int seq = 0;
    QString did; // did
    QString time; // datetime
};
struct Handle
{
    int seq = 0;
    QString did; // did
    QString handle; // handle
    QString time; // datetime
};
struct Migrate
{
    int seq = 0;
    QString did; // did
    QString migrateTo;
    QString time; // datetime
};
struct Tombstone
{
    int seq = 0;
    QString did; // did
    QString time; // datetime
};
struct Info
{
    QString name;
    QString message;
};
}

// tools.ozone.communication.defs
namespace ToolsOzoneCommunicationDefs {
struct TemplateView
{
    QString id;
    QString name; // Name of the template.
    QString subject; // Content of the template, can contain markdown and variable placeholders.
    QString contentMarkdown; // Subject of the message, used in emails.
    bool disabled = false;
    QString lastUpdatedBy; // did , DID of the user who last updated the template.
    QString createdAt; // datetime
    QString updatedAt; // datetime
};
}

// tools.ozone.moderation.defs
namespace ToolsOzoneModerationDefs {
enum class ModEventViewDetailEventType : int {
    none,
    event_ModEventTakedown,
    event_ModEventReverseTakedown,
    event_ModEventComment,
    event_ModEventReport,
    event_ModEventLabel,
    event_ModEventAcknowledge,
    event_ModEventEscalate,
    event_ModEventMute,
    event_ModEventEmail,
    event_ModEventResolveAppeal,
    event_ModEventDivert,
};
enum class ModEventViewDetailSubjectType : int {
    none,
    subject_RepoView,
    subject_RepoViewNotFound,
    subject_RecordView,
    subject_RecordViewNotFound,
};
enum class BlobViewDetailsType : int {
    none,
    details_ImageDetails,
    details_VideoDetails,
};
enum class SubjectStatusViewSubjectType : int {
    none,
    subject_ComAtprotoAdminDefs_RepoRef,
    subject_ComAtprotoRepoStrongRef_Main,
};
enum class ModEventViewEventType : int {
    none,
    event_ModEventTakedown,
    event_ModEventReverseTakedown,
    event_ModEventComment,
    event_ModEventReport,
    event_ModEventLabel,
    event_ModEventAcknowledge,
    event_ModEventEscalate,
    event_ModEventMute,
    event_ModEventEmail,
    event_ModEventResolveAppeal,
    event_ModEventDivert,
};
enum class ModEventViewSubjectType : int {
    none,
    subject_ComAtprotoAdminDefs_RepoRef,
    subject_ComAtprotoRepoStrongRef_Main,
};
struct ModEventTakedown
{
    QString comment;
    int durationInHours =
            0; // Indicates how long the takedown should be in effect before automatically expiring.
};
struct ModEventReverseTakedown
{
    QString comment; // Describe reasoning behind the reversal.
};
struct ModEventComment
{
    QString comment;
    bool sticky = false; // Make the comment persistent on the subject
};
struct ModEventReport
{
    QString comment;
    ComAtprotoModerationDefs::ReasonType reportType;
};
struct ModEventLabel
{
    QString comment;
    QList<QString> createLabelVals;
    QList<QString> negateLabelVals;
};
struct ModEventAcknowledge
{
    QString comment;
};
struct ModEventEscalate
{
    QString comment;
};
struct ModEventMute
{
    QString comment;
    int durationInHours = 0; // Indicates how long the subject should remain muted.
};
struct ModEventEmail
{
    QString subjectLine; // The subject line of the email sent to the user.
    QString content; // The content of the email sent to the user.
    QString comment; // Additional comment about the outgoing comm.
};
struct ModEventResolveAppeal
{
    QString comment; // Describe resolution.
};
struct ModEventDivert
{
    QString comment;
};
struct ModEventView
{
    int id = 0;
    // union start : event
    ModEventViewEventType event_type = ModEventViewEventType::none;
    ModEventTakedown event_ModEventTakedown;
    ModEventReverseTakedown event_ModEventReverseTakedown;
    ModEventComment event_ModEventComment;
    ModEventReport event_ModEventReport;
    ModEventLabel event_ModEventLabel;
    ModEventAcknowledge event_ModEventAcknowledge;
    ModEventEscalate event_ModEventEscalate;
    ModEventMute event_ModEventMute;
    ModEventEmail event_ModEventEmail;
    ModEventResolveAppeal event_ModEventResolveAppeal;
    ModEventDivert event_ModEventDivert;
    // union end : event
    // union start : subject
    ModEventViewSubjectType subject_type = ModEventViewSubjectType::none;
    ComAtprotoAdminDefs::RepoRef subject_ComAtprotoAdminDefs_RepoRef;
    ComAtprotoRepoStrongRef::Main subject_ComAtprotoRepoStrongRef_Main;
    // union end : subject
    QList<QString> subjectBlobCids;
    QString createdBy; // did
    QString createdAt; // datetime
    QString creatorHandle;
    QString subjectHandle;
};
typedef QString SubjectReviewState;
struct SubjectStatusView
{
    int id = 0;
    // union start : subject
    SubjectStatusViewSubjectType subject_type = SubjectStatusViewSubjectType::none;
    ComAtprotoAdminDefs::RepoRef subject_ComAtprotoAdminDefs_RepoRef;
    ComAtprotoRepoStrongRef::Main subject_ComAtprotoRepoStrongRef_Main;
    // union end : subject
    QList<QString> subjectBlobCids;
    QString subjectRepoHandle;
    QString updatedAt; // datetime , Timestamp referencing when the last update was made to the
                       // moderation status of the subject
    QString createdAt; // datetime , Timestamp referencing the first moderation status impacting
                       // event was emitted on the subject
    SubjectReviewState reviewState;
    QString comment; // Sticky comment on the subject.
    QString muteUntil; // datetime
    QString lastReviewedBy; // did
    QString lastReviewedAt; // datetime
    QString lastReportedAt; // datetime
    QString lastAppealedAt; // datetime , Timestamp referencing when the author of the subject
                            // appealed a moderation action
    bool takendown = false;
    bool appealed = false; // True indicates that the a previously taken moderator action was
                           // appealed against, by the author of the content. False indicates last
                           // appeal was resolved by moderators.
    QString suspendUntil; // datetime
    QList<QString> tags;
};
struct Moderation
{
    SubjectStatusView subjectStatus;
};
struct RepoView
{
    QString did; // did
    QString handle; // handle
    QString email;
    QString indexedAt; // datetime
    Moderation moderation;
    ComAtprotoServerDefs::InviteCode invitedBy;
    bool invitesDisabled = false;
    QString inviteNote;
};
struct RepoViewNotFound
{
    QString did; // did
};
struct RecordView
{
    QString uri; // at-uri
    QString cid; // cid
    QVariant value;
    QList<QString> blobCids;
    QString indexedAt; // datetime
    Moderation moderation;
    RepoView repo;
};
struct RecordViewNotFound
{
    QString uri; // at-uri
};
struct ImageDetails
{
    int width = 0;
    int height = 0;
};
struct VideoDetails
{
    int width = 0;
    int height = 0;
    int length = 0;
};
struct BlobView
{
    QString cid; // cid
    QString mimeType;
    int size = 0;
    QString createdAt; // datetime
    // union start : details
    BlobViewDetailsType details_type = BlobViewDetailsType::none;
    ImageDetails details_ImageDetails;
    VideoDetails details_VideoDetails;
    // union end : details
    Moderation moderation;
};
struct ModEventViewDetail
{
    int id = 0;
    // union start : event
    ModEventViewDetailEventType event_type = ModEventViewDetailEventType::none;
    ModEventTakedown event_ModEventTakedown;
    ModEventReverseTakedown event_ModEventReverseTakedown;
    ModEventComment event_ModEventComment;
    ModEventReport event_ModEventReport;
    ModEventLabel event_ModEventLabel;
    ModEventAcknowledge event_ModEventAcknowledge;
    ModEventEscalate event_ModEventEscalate;
    ModEventMute event_ModEventMute;
    ModEventEmail event_ModEventEmail;
    ModEventResolveAppeal event_ModEventResolveAppeal;
    ModEventDivert event_ModEventDivert;
    // union end : event
    // union start : subject
    ModEventViewDetailSubjectType subject_type = ModEventViewDetailSubjectType::none;
    RepoView subject_RepoView;
    RepoViewNotFound subject_RepoViewNotFound;
    RecordView subject_RecordView;
    RecordViewNotFound subject_RecordViewNotFound;
    // union end : subject
    QList<BlobView> subjectBlobs;
    QString createdBy; // did
    QString createdAt; // datetime
};
struct ModEventUnmute
{
    QString comment; // Describe reasoning behind the reversal.
};
struct ModEventTag
{
    QList<QString> add; // Tags to be added to the subject. If already exists, won't be duplicated.
    QList<QString> remove; // Tags to be removed to the subject. Ignores a tag If it doesn't exist,
                           // won't be duplicated.
    QString comment; // Additional comment about added/removed tags.
};
struct ModerationDetail
{
    SubjectStatusView subjectStatus;
};
struct RepoViewDetail
{
    QString did; // did
    QString handle; // handle
    QString email;
    QString indexedAt; // datetime
    ModerationDetail moderation;
    QList<ComAtprotoLabelDefs::Label> labels;
    ComAtprotoServerDefs::InviteCode invitedBy;
    QList<ComAtprotoServerDefs::InviteCode> invites;
    bool invitesDisabled = false;
    QString inviteNote;
    QString emailConfirmedAt; // datetime
};
struct RecordViewDetail
{
    QString uri; // at-uri
    QString cid; // cid
    QVariant value;
    QList<BlobView> blobs;
    QList<ComAtprotoLabelDefs::Label> labels;
    QString indexedAt; // datetime
    ModerationDetail moderation;
    RepoView repo;
};
}

}
Q_DECLARE_METATYPE(AtProtocolType::AppBskyFeedPost::Main)
Q_DECLARE_METATYPE(AtProtocolType::AppBskyFeedLike::Main)
Q_DECLARE_METATYPE(AtProtocolType::AppBskyFeedRepost::Main)
Q_DECLARE_METATYPE(AtProtocolType::AppBskyGraphListitem::Main)
Q_DECLARE_METATYPE(AtProtocolType::AppBskyActorProfile::Main)
Q_DECLARE_METATYPE(AtProtocolType::AppBskyGraphList::Main)
Q_DECLARE_METATYPE(AtProtocolType::AppBskyFeedThreadgate::Main)

#endif // LEXICONS_H
