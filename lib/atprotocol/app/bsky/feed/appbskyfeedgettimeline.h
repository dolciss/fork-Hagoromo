#ifndef APPBSKYFEEDGETTIMELINE_H
#define APPBSKYFEEDGETTIMELINE_H

#include "atprotocol/accessatprotocol.h"

namespace AtProtocolInterface {

class AppBskyFeedGetTimeline : public AccessAtProtocol
{
public:
    explicit AppBskyFeedGetTimeline(QObject *parent = nullptr);

    void getTimeline(const QString &algorithm, const int limit, const QString &cursor);

    const QList<AtProtocolType::AppBskyFeedDefs::FeedViewPost> &feedViewPostList() const;

protected:
    QString m_listKey;

    QList<AtProtocolType::AppBskyFeedDefs::FeedViewPost> m_feedViewPostList;

private:
    virtual bool parseJson(bool success, const QString reply_json);
};

}

#endif // APPBSKYFEEDGETTIMELINE_H
