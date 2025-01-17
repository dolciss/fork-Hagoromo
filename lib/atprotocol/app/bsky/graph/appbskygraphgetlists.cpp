#include "appbskygraphgetlists.h"
#include "atprotocol/lexicons_func.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QUrlQuery>

namespace AtProtocolInterface {

AppBskyGraphGetLists::AppBskyGraphGetLists(QObject *parent)
    : AccessAtProtocol { parent }, m_listKey("lists")
{
}

void AppBskyGraphGetLists::getLists(const QString &actor, const int limit, const QString &cursor)
{
    QUrlQuery url_query;
    if (!actor.isEmpty()) {
        url_query.addQueryItem(QStringLiteral("actor"), actor);
    }
    if (limit > 0) {
        url_query.addQueryItem(QStringLiteral("limit"), QString::number(limit));
    }
    if (!cursor.isEmpty()) {
        url_query.addQueryItem(QStringLiteral("cursor"), cursor);
    }

    get(QStringLiteral("xrpc/app.bsky.graph.getLists"), url_query);
}

const QList<AtProtocolType::AppBskyGraphDefs::ListView> &AppBskyGraphGetLists::listViewList() const
{
    return m_listViewList;
}

bool AppBskyGraphGetLists::parseJson(bool success, const QString reply_json)
{
    QJsonDocument json_doc = QJsonDocument::fromJson(reply_json.toUtf8());
    if (json_doc.isEmpty() || !json_doc.object().contains(m_listKey)) {
        success = false;
    } else {
        setCursor(json_doc.object().value("cursor").toString());
        for (const auto &value : json_doc.object().value(m_listKey).toArray()) {
            AtProtocolType::AppBskyGraphDefs::ListView data;
            AtProtocolType::AppBskyGraphDefs::copyListView(value.toObject(), data);
            m_listViewList.append(data);
        }
    }

    return success;
}

}
