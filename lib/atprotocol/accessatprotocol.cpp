#include "accessatprotocol.h"

#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkReply>
#include <QDebug>
#include <QFileInfo>
#include <QHttpMultiPart>

namespace AtProtocolInterface {

AccessAtProtocol::AccessAtProtocol(QObject *parent) : QObject { parent }
{
    connect(&m_manager, &QNetworkAccessManager::finished, [=](QNetworkReply *reply) {
        qDebug() << "reply" << reply->error() << reply->url();
        QString json = QString::fromUtf8(reply->readAll());

        if (reply->error() != QNetworkReply::NoError) {
            qDebug() << json;
            parseJson(QStringLiteral("{}"));
        } else {
            parseJson(json);
        }
    });
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

void AccessAtProtocol::get(const QString &endpoint, const QUrlQuery &query)
{
    if (accessJwt().isEmpty()) {
        qDebug() << "AccessAtProtocol::get()"
                 << "Emty accessJwt!";
        return;
    }

    qDebug() << "AccessAtProtocol::get()" << this << endpoint;

    QUrl url = QString("%1/%2").arg(service(), endpoint);
    url.setQuery(query);
    QNetworkRequest request(url);
    request.setRawHeader(QByteArray("Authorization"), QByteArray("Bearer ") + accessJwt().toUtf8());

    m_manager.get(request);
}

void AccessAtProtocol::post(const QString &endpoint, const QByteArray &json,
                            const bool with_auth_header)
{
    qDebug() << "AccessAtProtocol::post()" << this << endpoint << json;

    QNetworkRequest request(QUrl(QString("%1/%2").arg(service(), endpoint)));
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    if (with_auth_header) {
        if (accessJwt().isEmpty()) {
            qDebug() << "AccessAtProtocol::post()"
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
        qDebug() << "AccessAtProtocol::postWithImage()"
                 << "Empty accessJwt!";
        return;
    }
    if (!QFile::exists(path)) {
        qDebug() << "AccessAtProtocol::postWithImage()"
                 << "Not found" << path;
        return;
    }
    qDebug() << "AccessAtProtocol::postWithImage()" << this << endpoint << path;

    QFileInfo info(path);
    QNetworkRequest request(QUrl(QString("%1/%2").arg(service(), endpoint)));
    request.setRawHeader(QByteArray("Authorization"), QByteArray("Bearer ") + accessJwt().toUtf8());
    request.setHeader(QNetworkRequest::ContentTypeHeader,
                      QString("image/%1").arg(info.suffix().toLower()));

    QHttpMultiPart *multiPart = new QHttpMultiPart(QHttpMultiPart::FormDataType);
    QFile *file = new QFile(path, multiPart);
    if (!file->open(QIODevice::ReadOnly)) {
        qDebug() << "AccessAtProtocol::postWithImage()"
                 << "Not open" << path;
        delete multiPart;
        return;
    }

    QHttpPart imagePart;
    imagePart.setHeader(QNetworkRequest::ContentTypeHeader,
                        QString("image/%1").arg(info.suffix().toLower()));
    imagePart.setHeader(QNetworkRequest::ContentDispositionHeader,
                        QVariant("form-data; name=\"image\""));
    imagePart.setBodyDevice(file);

    multiPart->append(imagePart);

    QNetworkReply *reply = m_manager.post(request, multiPart);
    multiPart->setParent(reply); // 後で消すため
}

}
