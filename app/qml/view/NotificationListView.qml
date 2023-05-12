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

    property alias model: rootListView.model

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

        delegate: Frame {
            id: postFrame
            width: rootListView.width
            topPadding: 10
            leftPadding: 10
            rightPadding: 10
            bottomPadding: 10

            states: [
                State {
                    when: model.reason === NotificationListModel.ReasonReply
                    PropertyChanges { target: postFrame; bottomPadding: 0 }
                    PropertyChanges { target: postControls; visible: true }
                },
                State {
                    when: model.reason === NotificationListModel.ReasonQuote
                    PropertyChanges { target: postFrame; bottomPadding: 0 }
                    PropertyChanges { target: postControls; visible: true }
                }

            ]
            RowLayout {
                id: postLayout
                Image {
                    id: reasonImage
                    Layout.preferredWidth: 16
                    Layout.preferredHeight: 16
                    Layout.alignment: Qt.AlignTop
                    source: {
                        if(model.reason === NotificationListModel.ReasonLike){
                            return "../images/like.png"
                        }else if(model.reason === NotificationListModel.ReasonRepost){
                            return "../images/repost.png"
                        }else if(model.reason === NotificationListModel.ReasonFollow){
                            return "../images/add_user.png"
                        }else if(model.reason === NotificationListModel.ReasonMention){
                            return "../images/reply.png"
                        }else if(model.reason === NotificationListModel.ReasonReply){
                            return "../images/reply.png"
                        }else if(model.reason === NotificationListModel.ReasonQuote){
                            return "../images/reply.png"
                        }else{
                            return "../images/like.png"
                        }
                    }
                    layer.enabled: true
                    layer.effect: ColorOverlay {
                        color: {
                            if(model.reason === NotificationListModel.ReasonLike){
                                return Material.color(Material.Pink)
                            }else if(model.reason === NotificationListModel.ReasonRepost){
                                return Material.color(Material.Green)
                            }else if(model.reason === NotificationListModel.ReasonFollow){
                                return Material.color(Material.LightBlue)
                            }else if(model.reason === NotificationListModel.ReasonMention){
                                return Material.color(Material.Blue)
                            }else if(model.reason === NotificationListModel.ReasonReply){
                                return Material.color(Material.BlueGrey)
                            }else if(model.reason === NotificationListModel.ReasonQuote){
                                return Material.color(Material.Lime)
                            }else{
                                return Material.color(Material.Grey)
                            }
                        }
                    }
                }

                ColumnLayout {
                    id: bodyLayout
                    Layout.fillWidth: true
                    spacing: 5

                    property int basisWidth: postFrame.width - postFrame.leftPadding - postFrame.rightPadding -
                                             postLayout.spacing - reasonImage.width - avatorImage.width

                    RowLayout {
                        AvatarImage {
                            id: avatorImage
                            Layout.preferredWidth: 16
                            Layout.preferredHeight: 16
                            source: model.avatar
                        }
                        Author {
                            Layout.preferredWidth: bodyLayout.basisWidth
                            Layout.maximumWidth: bodyLayout.basisWidth
//                            Layout.fillWidth: true
                            displayName: model.displayName
                            handle: model.handle
                            indexedAt: model.indexedAt
                        }
                    }

//                    Label {
//                        text: "test"
//                    }

                    PostControls {
                        id: postControls
                        visible: false
                        replyButton.iconText: "0" //model.replyCount
                        repostButton.iconText: "0" //model.repostCount
                        likeButton.iconText: "0" //model.likeCount
                    }

                }
            }
        }
    }
}
