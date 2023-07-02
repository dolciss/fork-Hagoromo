import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15
import QtGraphicalEffects 1.15

RowLayout {
    id: reactionAuthor
    clip: true

    property alias source: iconImage.source
    property alias displayName: displayNameLabel.text
    property alias handle: handleLabel.text
    property color color: Material.color(Material.Grey)

    Image {
        id: iconImage
        Layout.preferredWidth: 12
        Layout.preferredHeight: 12
        layer.enabled: true
        layer.effect: ColorOverlay {
            color: reactionAuthor.color
        }
    }
    Label {
        id: displayNameLabel
        Layout.alignment: Qt.AlignCenter
//        Layout.maximumWidth: reactionAuthor.width - iconImage.width - handleLabel.width - reactionAuthor.spacing * 2
        font.pointSize: 8
        color: reactionAuthor.color
        elide: Text.ElideRight
    }
    Label {
        id: handleLabel
        Layout.alignment: Qt.AlignCenter
        Layout.fillWidth: true
        font.pointSize: 8
        opacity: 0.8
        color: reactionAuthor.color
    }
}