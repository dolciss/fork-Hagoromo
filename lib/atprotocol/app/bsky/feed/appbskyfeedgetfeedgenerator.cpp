#include "appbskyfeedgetfeedgenerator.h"
#include "atprotocol/lexicons_func.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QUrlQuery>

namespace AtProtocolInterface {

AppBskyFeedGetFeedGenerator::AppBskyFeedGetFeedGenerator(QObject *parent)
    : AccessAtProtocol { parent }
{
}

void AppBskyFeedGetFeedGenerator::getFeedGenerator(const QString &feed)
{
    QUrlQuery url_query;
    if (!feed.isEmpty()) {
        url_query.addQueryItem(QStringLiteral("feed"), feed);
    }

    get(QStringLiteral("xrpc/app.bsky.feed.getFeedGenerator"), url_query);
}

const AtProtocolType::AppBskyFeedDefs::GeneratorView &
AppBskyFeedGetFeedGenerator::generatorView() const
{
    return m_generatorView;
}

bool AppBskyFeedGetFeedGenerator::parseJson(bool success, const QString reply_json)
{
    QJsonDocument json_doc = QJsonDocument::fromJson(reply_json.toUtf8());
    if (json_doc.isEmpty()) {
        success = false;
    } else {
        AtProtocolType::AppBskyFeedDefs::copyGeneratorView(
                json_doc.object().value("view").toObject(), m_generatorView);
    }

    return success;
}

}
