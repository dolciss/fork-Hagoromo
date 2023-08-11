#include "authorfeedlistmodel.h"

#include "atprotocol/app/bsky/feed/appbskyfeedgetauthorfeed.h"

using AtProtocolInterface::AppBskyFeedGetAuthorFeed;

AuthorFeedListModel::AuthorFeedListModel(QObject *parent) : TimelineListModel { parent }
{
    setDisplayInterval(0);
}

void AuthorFeedListModel::getLatest()
{
    if (running())
        return;
    setRunning(true);

    updateContentFilterLabels([=]() {
        AppBskyFeedGetAuthorFeed *timeline = new AppBskyFeedGetAuthorFeed(this);
        connect(timeline, &AppBskyFeedGetAuthorFeed::finished, [=](bool success) {
            if (success) {
                copyFrom(timeline);
            } else {
                emit errorOccured(timeline->errorMessage());
            }
            QTimer::singleShot(100, this, &AuthorFeedListModel::displayQueuedPosts);
            timeline->deleteLater();
        });

        AppBskyFeedGetAuthorFeed::FilterType filter_type;
        if (filter() == AuthorFeedListModelFilterType::PostsNoReplies) {
            filter_type = AppBskyFeedGetAuthorFeed::FilterType::PostsNoReplies;
        } else if (filter() == AuthorFeedListModelFilterType::PostsWithMedia) {
            filter_type = AppBskyFeedGetAuthorFeed::FilterType::PostsWithMedia;
        } else {
            filter_type = AppBskyFeedGetAuthorFeed::FilterType::PostsWithReplies;
        }
        timeline->setAccount(account());
        timeline->getAuthorFeed(authorDid(), -1, QString(), filter_type);
    });
}

QString AuthorFeedListModel::authorDid() const
{
    return m_authorDid;
}

void AuthorFeedListModel::setAuthorDid(const QString &newAuthorDid)
{
    if (m_authorDid == newAuthorDid)
        return;
    m_authorDid = newAuthorDid;
    emit authorDidChanged();
}

AuthorFeedListModel::AuthorFeedListModelFilterType AuthorFeedListModel::filter() const
{
    return m_filter;
}

void AuthorFeedListModel::setFilter(AuthorFeedListModelFilterType newFilter)
{
    if (m_filter == newFilter)
        return;
    m_filter = newFilter;
    emit filterChanged();
}
