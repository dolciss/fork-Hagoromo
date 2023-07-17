import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15

import tech.relog.hagoromo.reporter 1.0

import "../controls"
import "../data"
import "../parts"

Dialog {
    id: reportDialog
    modal: true
    x: (parent.width - width) * 0.5
    y: (parent.height - height) * 0.5

    title: qsTr("Report post")

    property string targetUri: ""
    property string targetCid: ""
    property alias account: account

    onClosed: reportTypeButtonGroup.checkState = Qt.Unchecked

    Account {
        id: account
    }
    Reporter {
        id: reporter
        onFinished: (success) => reportDialog.accept()
    }

    ButtonGroup {
        id: reportTypeButtonGroup
        buttons: reportTypeLayout.children
    }

    ColumnLayout {
        id: reportTypeLayout
        Layout.rightMargin: 10
//        RowLayout {
//            AvatarImage {
//                Layout.preferredWidth: 24
//                Layout.preferredHeight: 24
//                source: account.avatar
//            }
//            Label {
//                text: account.handle
//            }
//        }

        RadioButtonEx {
            mainText: qsTr("Spam")
            description: qsTr("Excessive mentions or replies")
            property int reason: Reporter.ReasonSpam
        }
        RadioButtonEx {
            mainText: qsTr("Unwanted Sexual Content")
            description: qsTr("Nudity or pornography not labeled as such")
            property int reason: Reporter.ReasonSexual
        }
        RadioButtonEx {
            mainText: qsTr("Anti-Social Behavior")
            description: qsTr("Harassment, trolling, or intolerance")
            property int reason: Reporter.ReasonRude
        }
        RadioButtonEx {
            mainText: qsTr("Illegal and Urgent")
            description: qsTr("Glaring violations of law or terms of service")
            property int reason: Reporter.ReasonViolation
        }
        RadioButtonEx {
            mainText: qsTr("Other")
            description: qsTr("An issue not included in these options")
            property int reason: Reporter.ReasonOther
        }
        RowLayout {
            Button {
                Layout.alignment: Qt.AlignLeft
                flat: true
                text: qsTr("Cancel")
                onClicked: reportDialog.close()
            }
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: 1
            }
            Button {
                Layout.alignment: Qt.AlignRight
                enabled: reportTypeButtonGroup.checkState === Qt.PartiallyChecked && !reporter.running
                text: qsTr("Send report")
                onClicked: {
                    reporter.setAccount(account.service, account.did, account.handle,
                                        account.email, account.accessJwt, account.refreshJwt)
                    reporter.reportPost(targetUri, targetCid, reportTypeButtonGroup.checkedButton.reason)
                }
                BusyIndicator {
                    anchors.fill: parent
                    visible: reporter.running
                }
            }
        }
    }
}
