import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15
import QtGraphicalEffects 1.15

import tech.relog.hagoromo.notificationlistmodel 1.0

import "../parts"

ScrollView {
    ScrollBar.vertical.policy: ScrollBar.AlwaysOn
    ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
    clip: true

    property alias listView: rootListView
    property alias model: rootListView.model

    signal requestedReply(string cid, string uri,
                          string reply_root_cid, string reply_root_uri,
                          string avatar, string display_name, string handle, string indexed_at, string text)
    signal requestedRepost(string cid, string uri)
    signal requestedQuote(string cid, string uri, string avatar, string display_name, string handle, string indexed_at, string text)
    signal requestedLike(string cid, string uri)
    signal requestedViewThread(string uri)
    signal requestedViewImages(int index, string paths)

    ListView {
        id: rootListView
        anchors.fill: parent
        anchors.rightMargin: parent.ScrollBar.vertical.width

        model: NotificationListModel {
            id: listNotificationListModel
        }

        header: ItemDelegate {
            width: rootListView.width
            height: 24
            display: AbstractButton.IconOnly
            icon.source: listNotificationListModel.running ? "" : "../images/expand_less.png"
            onClicked: listNotificationListModel.getLatest()

            BusyIndicator {
                anchors.centerIn: parent
                width: 24
                height: 24
                visible: listNotificationListModel.running
            }
        }
        footer: BusyIndicator {
            width: rootListView.width
            height: 24
            visible: listNotificationListModel.running && listNotificationListModel.rowCount() > 0
        }

        delegate: NotificationDelegate {
            reason: model.reason
            postAvatarImage.source: model.avatar
            postAuthor.displayName: model.displayName
            postAuthor.handle: model.handle
            postAuthor.indexedAt: model.indexedAt
            recordText: model.recordText

            recordDisplayName: model.recordDisplayName
            recordHandle: model.recordHandle
            recordAvatar: model.recordAvatar
            recordIndexedAt: model.recordIndexedAt
            recordRecordText: model.recordRecordText

            onClicked: {
                if(model.reason === NotificationListModel.ReasonLike ||
                        model.reason === NotificationListModel.ReasonRepost){
                    if(model.recordUri.length > 0)
                        requestedViewThread(model.recordUri)
                }else if(model.reason === NotificationListModel.ReasonFollow){
                }else if(model.reason === NotificationListModel.ReasonMention){
                }else if(model.reason === NotificationListModel.ReasonReply ||
                         model.reason === NotificationListModel.ReasonQuote){
                    requestedViewThread(model.uri)
                }
            }

            recordFrame.onClicked: {
                if(model.reason === NotificationListModel.ReasonQuote){
                    requestedViewThread(model.recordUri)
                }
            }
        }
    }
}
