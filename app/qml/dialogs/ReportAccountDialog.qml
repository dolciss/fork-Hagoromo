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

    title: qsTr("Report account")

    property string targetDid: ""
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

        RadioButtonEx {
            mainText: qsTr("Misleading Account")
            description: qsTr("Impersonation or false claims about identity or affiliation")
            property int reason: Reporter.ReasonMisleading
        }
        RadioButtonEx {
            mainText: qsTr("Frequently Posts Unwanted Content")
            description: qsTr("Spam; excessive mentions or replies")
            property int reason: Reporter.ReasonSpam
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
                    reporter.reportAccount(targetDid, reportTypeButtonGroup.checkedButton.reason)
                }
                BusyIndicator {
                    anchors.fill: parent
                    visible: reporter.running
                }
            }
        }
    }
}
