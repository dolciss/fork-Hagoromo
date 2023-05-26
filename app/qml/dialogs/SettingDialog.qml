import QtQuick 2.15
import QtQuick.Controls 2.15
import QtQuick.Layouts 1.15
import QtQuick.Controls.Material 2.15
import Qt.labs.settings 1.0

import tech.relog.hagoromo.encryption 1.0

Dialog {
    id: settingDialog
    modal: true
    x: (parent.width - width) * 0.5
    y: (parent.height - height) * 0.5

    property int parentWidth: parent.width

    property alias settings: settings


    // 行間と文字間も調整できると良いかも


    Encryption {
        id: encryption
    }

    Settings {
        id: settings
        property int theme: Material.Light
        property color accent: Material.color(Material.Pink)

        property string translateApiUrl: "https://api-free.deepl.com/v2/translate"
        property string translateApiKey: ""
        property string translateTargetLanguage: "JA"



        Component.onCompleted: {
            setRadioButton(themeButtonGroup.buttons, settings.theme)
            setRadioButton(accentButtonGroup.buttons, settings.accent)
            translateApiUrlText.text = settings.translateApiUrl
            translateApiKeyText.text = encryption.decrypt(settings.translateApiKey)
            translateTargetLanguageCombo.currentIndex = translateTargetLanguageCombo.indexOfValue(settings.translateTargetLanguage)
        }

        function setRadioButton(buttons, value){
            for(var i=0; i<buttons.length; i++){
                if(buttons[i].value === value){
                    buttons[i].checked = true
                }
            }
        }
    }


    ButtonGroup {
        id: themeButtonGroup
        buttons: themeRowlayout.children
    }
    ButtonGroup {
        id: accentButtonGroup
        buttons: accentGridLayout.children
    }

    ColumnLayout {
        TabBar {
            id: tabBar
            Layout.fillWidth: true
            TabButton {
                font.capitalization: Font.MixedCase
                text: qsTr("General")
            }
            TabButton {
                font.capitalization: Font.MixedCase
                text: qsTr("Translate")
            }
        }

        SwipeView {
            currentIndex: tabBar.currentIndex
            interactive: false
            clip: true

            // General Page
            ColumnLayout {
                RowLayout {
                    id: themeRowlayout
                    Label {
                        text: qsTr("Theme") + " : "
                    }
                    RadioButton {
                        property int value: Material.Light
                        text: qsTr("Light")
                    }
                    RadioButton {
                        property int value: Material.Dark
                        text: qsTr("Dark")
                    }
                }
                Label {
                    text: qsTr("Accent color") + " : "
                }
                GridLayout {
                    id: accentGridLayout
                    columns: 9
                    columnSpacing: 1
                    rowSpacing: 1
                    Repeater {
                        model: [Material.Red, Material.Pink, Material.Purple, Material.DeepPurple,
                            Material.Indigo, Material.Blue, Material.LightBlue, Material.Cyan,
                            Material.Teal, Material.Green, Material.LightGreen, Material.lime,
                            Material.Yellow, Material.Amber, Material.Orange, Material.DeepOrange,
                            Material.Brown, Material.BlueGrey ]
                        Button {
                            id: colorSelectButton
                            Layout.preferredWidth: 30
                            Layout.preferredHeight: 30
                            topInset: 1
                            leftInset: 1
                            rightInset: 1
                            bottomInset: 1
                            background: Rectangle {
                                color: Material.color(modelData)
                                border.color: colorSelectButton.checked ? Material.foreground : Material.background
                                border.width: 2
                                radius: 5
                            }
                            checkable: true
                            property color value: Material.color(modelData)
                        }
                    }
                }
            }

            // Translate Page
            GridLayout {
                columns: 2
                Label {
                    text: qsTr("Api Url")
                }
                TextField {
                    id: translateApiUrlText
                    Layout.preferredWidth: 350
                    text: ""
                }
                Label {
                    text: qsTr("Api Key")
                }
                TextField {
                    id: translateApiKeyText
                    Layout.preferredWidth: 350
                    echoMode: TextInput.Password
                    text: ""
                }
                Label {
                    text: qsTr("Target language")
                }
                ComboBox {
                    id: translateTargetLanguageCombo
                    Layout.fillWidth: true
                    textRole: "text"
                    valueRole: "value"
                    model: ListModel {
                        ListElement { value: "BG"; text: qsTr("Bulgarian") }
                        ListElement { value: "ZH"; text: qsTr("Chinese (simplified)") }
                        ListElement { value: "CS"; text: qsTr("Czech") }
                        ListElement { value: "DA"; text: qsTr("Danish") }
                        ListElement { value: "NL"; text: qsTr("Dutch") }
                        ListElement { value: "EN-US"; text: qsTr("English (American)") }
                        ListElement { value: "EN-GB"; text: qsTr("English (British)") }
                        ListElement { value: "ET"; text: qsTr("Estonian") }
                        ListElement { value: "FI"; text: qsTr("Finnish") }
                        ListElement { value: "FR"; text: qsTr("French") }
                        ListElement { value: "DE"; text: qsTr("German") }
                        ListElement { value: "EL"; text: qsTr("Greek") }
                        ListElement { value: "HU"; text: qsTr("Hungarian") }
                        ListElement { value: "ID"; text: qsTr("Indonesian") }
                        ListElement { value: "IT"; text: qsTr("Italian") }
                        ListElement { value: "JA"; text: qsTr("Japanese") }
                        ListElement { value: "KO"; text: qsTr("Korean") }
                        ListElement { value: "LV"; text: qsTr("Latvian") }
                        ListElement { value: "LT"; text: qsTr("Lithuanian") }
                        ListElement { value: "NB"; text: qsTr("Norwegian (Bokmål)") }
                        ListElement { value: "PL"; text: qsTr("Polish") }
                        ListElement { value: "PT-BR"; text: qsTr("Portuguese (Brazilian)") }
                        ListElement { value: "PT-PT"; text: qsTr("Portuguese (excluding Brazilian)") }
                        ListElement { value: "RO"; text: qsTr("Romanian") }
                        ListElement { value: "RU"; text: qsTr("Russian") }
                        ListElement { value: "SK"; text: qsTr("Slovak") }
                        ListElement { value: "SL"; text: qsTr("Slovenian") }
                        ListElement { value: "ES"; text: qsTr("Spanish") }
                        ListElement { value: "SV"; text: qsTr("Swedish") }
                        ListElement { value: "TR"; text: qsTr("Turkish") }
                        ListElement { value: "UK"; text: qsTr("Ukrainian") }
                    }
                }
            }


        }


//        Label {
//            text: qsTr("Font")
//        }
//        ComboBox {
//            id: fontCombo
//            Layout.preferredWidth: 300
//            model: Qt.fontFamilies()
//            delegate: ItemDelegate {
//                text: modelData
//                width: fontCombo.width
//            }
//        }


        RowLayout {
            Button {
                flat: true
                text: qsTr("Cancel")
                onClicked: settingDialog.reject()
            }
            Item {
                Layout.fillWidth: true
                Layout.preferredHeight: 1
            }
            Button {
                text: qsTr("OK")
                onClicked: {
                    settings.theme = themeButtonGroup.checkedButton.value
                    settings.accent = accentButtonGroup.checkedButton.value
                    settings.translateApiUrl = translateApiUrlText.text
                    settings.translateApiKey = encryption.encrypt(translateApiKeyText.text)
                    settings.translateTargetLanguage = translateTargetLanguageCombo.currentValue

                    settingDialog.accept()
                }
            }
        }
    }
}
