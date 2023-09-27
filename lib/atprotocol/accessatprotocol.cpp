#include "accessatprotocol.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QDebug>
#include <QFileInfo>
#include <QHttpMultiPart>
#include <QDateTime>
#include <QUrlQuery>
#include <QMimeDatabase>

#define LOG_DATETIME QDateTime::currentDateTime().toString("yyyy/MM/dd hh:mm:ss")

namespace AtProtocolInterface {

AccessAtProtocol::AccessAtProtocol(QObject *parent) : QObject { parent }
{
    connect(&m_manager, &QNetworkAccessManager::finished, [=](QNetworkReply *reply) {
        qDebug() << LOG_DATETIME << reply->error() << reply->url();

        bool success = false;
        if (checkReply(reply)) {
            success = parseJson(true, m_replyJson);
        }
        emit finished(success);

        reply->deleteLater();
    });
}

const AccountData &AccessAtProtocol::account() const
{
    return m_account;
}

void AccessAtProtocol::setAccount(const AccountData &account)
{
    m_account.service = account.service;
    m_account.identifier.clear();
    m_account.password.clear();

    m_account.did = account.did;
    m_account.handle = account.handle;
    m_account.email = account.email;
    m_account.accessJwt = account.accessJwt;
    m_account.refreshJwt = account.refreshJwt;
    m_account.status = account.status;
}

void AccessAtProtocol::setSession(const QString &did, const QString &handle, const QString &email,
                                  const QString &accessJwt, const QString &refresh_jwt)
{
    m_account.did = did;
    m_account.handle = handle;
    m_account.email = email;
    m_account.accessJwt = accessJwt;
    m_account.refreshJwt = refresh_jwt;
}

QString AccessAtProtocol::service() const
{
    return m_account.service;
}

void AccessAtProtocol::setService(const QString &newService)
{
    m_account.service = newService;
}

QString AccessAtProtocol::did() const
{
    return m_account.did;
}

QString AccessAtProtocol::handle() const
{
    return m_account.handle;
}

QString AccessAtProtocol::email() const
{
    return m_account.email;
}

QString AccessAtProtocol::accessJwt() const
{
    return m_account.accessJwt;
}

QString AccessAtProtocol::refreshJwt() const
{
    return m_account.refreshJwt;
}

void AccessAtProtocol::get(const QString &endpoint, const QUrlQuery &query,
                           const bool with_auth_header)
{
    if (accessJwt().isEmpty() && with_auth_header) {
        qCritical() << LOG_DATETIME << "AccessAtProtocol::get()"
                    << "Emty accessJwt!";
        return;
    }

    qDebug() << LOG_DATETIME << "AccessAtProtocol::get()" << this;
    qDebug().noquote() << "   " << handle();
    qDebug().noquote() << "   " << endpoint;
    qDebug().noquote() << "   " << query.toString();

    QUrl url = QString("%1/%2").arg(service(), endpoint);
    url.setQuery(query);
    QNetworkRequest request(url);
    if (with_auth_header) {
        request.setRawHeader(QByteArray("Authorization"),
                             QByteArray("Bearer ") + accessJwt().toUtf8());
    }

    m_manager.get(request);
}

void AccessAtProtocol::post(const QString &endpoint, const QByteArray &json,
                            const bool with_auth_header)
{
    qDebug() << LOG_DATETIME << "AccessAtProtocol::post()" << this;
    qDebug().noquote() << "   " << handle();
    qDebug().noquote() << "   " << endpoint;
    qDebug().noquote() << "   " << json;

    QNetworkRequest request(QUrl(QString("%1/%2").arg(service(), endpoint)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (with_auth_header) {
        if (accessJwt().isEmpty()) {
            qCritical() << LOG_DATETIME << "AccessAtProtocol::post()"
                        << "Empty accessJwt!";
            return;
        }

        request.setRawHeader(QByteArray("Authorization"),
                             QByteArray("Bearer ") + accessJwt().toUtf8());
    }

    m_manager.post(request, json);
}

void AccessAtProtocol::postWithImage(const QString &endpoint, const QString &path)
{
    if (accessJwt().isEmpty()) {
        qCritical() << LOG_DATETIME << "AccessAtProtocol::postWithImage()"
                    << "Empty accessJwt!";
        return;
    }
    if (!QFile::exists(path)) {
        qCritical() << LOG_DATETIME << "AccessAtProtocol::postWithImage()"
                    << "Not found" << path;
        return;
    }
    qDebug() << LOG_DATETIME << "AccessAtProtocol::postWithImage()" << this << endpoint << path;

    QFileInfo info(path);
    QNetworkRequest request(QUrl(QString("%1/%2").arg(service(), endpoint)));
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QString("image/%1").arg(info.suffix().toLower()));
    //    QNetworkRequest request(
    //        QUrl(QString("%1/%2").arg(/*service()*/ "https://relog.tech", endpoint)));
    request.setAttribute(QNetworkRequest::CacheLoadControlAttribute,
                         QNetworkRequest::AlwaysNetwork);
    request.setAttribute(QNetworkRequest::CacheSaveControlAttribute, false);
    request.setAttribute(QNetworkRequest::AuthenticationReuseAttribute, QNetworkRequest::Manual);
    //    request.setAttribute(QNetworkRequest::DoNotBufferUploadDataAttribute, true);
    request.setAttribute(QNetworkRequest::HttpPipeliningAllowedAttribute, false);
    request.setAttribute(QNetworkRequest::Http2AllowedAttribute, false);
    request.setAttribute(QNetworkRequest::SpdyAllowedAttribute, false);
    request.setRawHeader(QByteArray("Accept"), QByteArray("*/*"));
    //    request.setRawHeader(QByteArray("Cache-Control"), QByteArray("no-cache"));
    request.setRawHeader(QByteArray("Authorization"), QByteArray("Bearer ") + accessJwt().toUtf8());
    request.setHeader(QNetworkRequest::ContentTypeHeader, mime.mimeTypeForFile(info).name());
    request.setTransferTimeout(10000);

    qDebug() << "  QNetworkRequest::CacheLoadControlAttribute"
             << request.attribute(QNetworkRequest::CacheLoadControlAttribute);
    qDebug() << "  QNetworkRequest::CacheSaveControlAttribute"
             << request.attribute(QNetworkRequest::CacheSaveControlAttribute);
    qDebug() << "  QNetworkRequest::AuthenticationReuseAttribute"
             << request.attribute(QNetworkRequest::AuthenticationReuseAttribute);
    qDebug() << "  QNetworkRequest::DoNotBufferUploadDataAttribute"
             << request.attribute(QNetworkRequest::DoNotBufferUploadDataAttribute);
    qDebug() << "  QNetworkRequest::HttpPipeliningAllowedAttribute"
             << request.attribute(QNetworkRequest::HttpPipeliningAllowedAttribute);
    qDebug() << "  QNetworkRequest::Http2AllowedAttribute"
             << request.attribute(QNetworkRequest::Http2AllowedAttribute);
    qDebug() << "  QNetworkRequest::SpdyAllowedAttribute"
             << request.attribute(QNetworkRequest::SpdyAllowedAttribute);
    qDebug() << "  transferTimeout" << request.transferTimeout();

    QFile *file = new QFile(path);
    if (!file->open(QIODevice::ReadOnly)) {
        qCritical() << LOG_DATETIME << "AccessAtProtocol::postWithImage()"
                    << "Not open" << path;
        delete file;
        return;
    }
    //    request.setHeader(QNetworkRequest::ContentLengthHeader, file->size());
    qDebug() << "  file->size()" << file->size();

    QNetworkReply *reply = m_manager->post(request, file->readAll());
    file->setParent(reply);
    connect(reply, &QNetworkReply::finished, [=]() {
        qDebug() << LOG_DATETIME << reply->error() << reply->url().toString();

        bool success = false;
        if (checkReply(reply)) {
            success = parseJson(true, m_replyJson);
        }
        emit finished(success);

        reply->deleteLater();
    });
    connect(reply, &QNetworkReply::uploadProgress, [=](qint64 bytesSent, qint64 bytesTotal) {
        if (bytesTotal > 0) {
            qDebug() << LOG_DATETIME << "uploadProgress : bytesSent" << bytesSent << "bytesTotal"
                     << bytesTotal << (100 * bytesSent / bytesTotal);
        } else {
            qDebug() << LOG_DATETIME << "uploadProgress : bytesSent" << bytesSent << "bytesTotal";
        }
    });
    connect(reply, &QNetworkReply::downloadProgress, [=](qint64 bytesReceived, qint64 bytesTotal) {
        if (bytesTotal > 0) {
            qDebug() << LOG_DATETIME << "downloadProgress : bytesReceived" << bytesReceived
                     << "bytesTotal" << bytesTotal << (100 * bytesReceived / bytesTotal);
        }
    });
    connect(reply, &QNetworkReply::encrypted, [=]() { qDebug() << LOG_DATETIME << "encrypted"; });
    connect(reply, &QNetworkReply::errorOccurred, [=](QNetworkReply::NetworkError code) {
        qDebug() << LOG_DATETIME << "errorOccurred" << code;
        qDebug() << "  QNetworkRequest::HttpStatusCodeAttribute"
                 << reply->attribute(QNetworkRequest::HttpStatusCodeAttribute);
        qDebug() << "  QNetworkRequest::HttpReasonPhraseAttribute"
                 << reply->attribute(QNetworkRequest::HttpReasonPhraseAttribute);
        qDebug() << "  QNetworkRequest::SourceIsFromCacheAttribute"
                 << reply->attribute(QNetworkRequest::SourceIsFromCacheAttribute);
        qDebug() << "  QNetworkRequest::HttpPipeliningWasUsedAttribute"
                 << reply->attribute(QNetworkRequest::HttpPipeliningWasUsedAttribute);
        qDebug() << "  QNetworkRequest::SpdyWasUsedAttribute"
                 << reply->attribute(QNetworkRequest::SpdyWasUsedAttribute);
        qDebug() << "  QNetworkRequest::Http2WasUsedAttribute"
                 << reply->attribute(QNetworkRequest::Http2WasUsedAttribute);
        qDebug() << "  QNetworkRequest::OriginalContentLengthAttribute"
                 << reply->attribute(QNetworkRequest::OriginalContentLengthAttribute).toInt();
    });
    connect(reply, &QNetworkReply::metaDataChanged, [=]() {
        qDebug() << LOG_DATETIME << "metaDataChanged";
        for (const auto &header : reply->rawHeaderPairs()) {
            qDebug() << LOG_DATETIME << QString("  %1:%2").arg(header.first, header.second);
        }
    });
    connect(reply, &QNetworkReply::preSharedKeyAuthenticationRequired,
            [=](QSslPreSharedKeyAuthenticator *authenticator) {
                qDebug() << LOG_DATETIME << "preSharedKeyAuthenticationRequired" << authenticator;
            });
    connect(reply, &QNetworkReply::redirectAllowed,
            [=]() { qDebug() << LOG_DATETIME << "redirectAllowed"; });
    connect(reply, &QNetworkReply::redirected,
            [=](const QUrl &url) { qDebug() << LOG_DATETIME << "redirected" << url.toString(); });
    connect(reply, &QNetworkReply::sslErrors, [=](const QList<QSslError> &errors) {
        qDebug() << LOG_DATETIME << "sslErrors" << errors;
    });
    connect(reply, &QNetworkReply::readyRead, [=]() {
        qDebug() << LOG_DATETIME << "readyRead";
        qDebug() << LOG_DATETIME << "  reply->size()" << reply->size();
        qDebug() << LOG_DATETIME << "  reply->isSequential()" << reply->isSequential();
        qDebug() << LOG_DATETIME << "  reply->bytesAvailable()" << reply->bytesAvailable();
    });

    qDebug() << LOG_DATETIME << "reply(before)";
    for (const auto &header : reply->rawHeaderPairs()) {
        qDebug() << LOG_DATETIME << QString("  before %1:%2").arg(header.first, header.second);
    }
    qDebug() << LOG_DATETIME << "  reply->bytesToWrite()" << reply->bytesToWrite();
}

bool AccessAtProtocol::checkReply(QNetworkReply *reply)
{
    bool status = false;
    m_replyJson = QString::fromUtf8(reply->readAll());
    m_errorCode.clear();
    m_errorMessage.clear();

#ifdef QT_DEBUG
    for (const auto &header : reply->rawHeaderPairs()) {
        if (header.first.toLower().startsWith("ratelimit-")) {
            if (header.first.toLower() == "ratelimit-reset") {
                qDebug() << LOG_DATETIME << header.first
                         << QDateTime::fromSecsSinceEpoch(header.second.toInt())
                                    .toString("yyyy/MM/dd hh:mm:ss");
            } else {
                qDebug() << LOG_DATETIME << header.first << header.second;
            }
        }
    }
#endif

    QJsonDocument json_doc = QJsonDocument::fromJson(m_replyJson.toUtf8());
    if (reply->error() != QNetworkReply::NoError) {
        if (json_doc.object().contains("error") && json_doc.object().contains("error")) {
            m_errorCode = json_doc.object().value("error").toString();
            m_errorMessage = json_doc.object().value("message").toString();
        } else {
            m_errorCode = QStringLiteral("Other");
            m_errorMessage = m_replyJson;
        }
        if (m_errorCode == "RateLimitExceeded") {
            m_errorMessage += "\n";
            for (const auto &header : reply->rawHeaderPairs()) {
                if (header.first.toLower().startsWith("ratelimit-")) {
                    if (header.first.toLower() == "ratelimit-reset") {
                        m_errorMessage += QString("\n%1:%2").arg(
                                header.first,
                                QDateTime::fromSecsSinceEpoch(header.second.toInt())
                                        .toString("yyyy/MM/dd hh:mm:ss"));
                    } else {
                        m_errorMessage += QString("\n%1:%2").arg(header.first, header.second);
                    }
                }
            }
        }
        qCritical() << LOG_DATETIME << m_errorCode << m_errorMessage;
        qCritical() << LOG_DATETIME << m_replyJson;
    } else {
        status = true;
    }
    return status;
}

QString AccessAtProtocol::cursor() const
{
    return m_cursor;
}

void AccessAtProtocol::setCursor(const QString &newCursor)
{
    m_cursor = newCursor;
}

QString AccessAtProtocol::errorMessage() const
{
    return m_errorMessage;
}

QString AccessAtProtocol::replyJson() const
{
    return m_replyJson;
}

QString AccessAtProtocol::errorCode() const
{
    return m_errorCode;
}

}
