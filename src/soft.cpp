#include <SPI.h>
#include <MFRC522.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <EEPROM.h>
#include "RTClib.h"
RTC_DS3231 rtc;


#define I2C_ADDR 0x3F
#define LCD_COLUMNS 16
#define LCD_LINES 2
LiquidCrystal_I2C lcd(I2C_ADDR, LCD_COLUMNS, LCD_LINES);

#define SS_PIN 10
#define RST_PIN 9
MFRC522 mfrc522(SS_PIN, RST_PIN);

#define BUTTON1_PIN 2 // Select
#define BUTTON2_PIN 3 // Confirm

#define DEBOUNCE_MS 200
#define MAX_UIDS 5
#define UID_SIZE 4
#define EEPROM_LOG_START 0
#define EEPROM_INDEX_ADDR 100

volatile bool btn1Pressed = false;
volatile bool btn2Pressed = false;

volatile unsigned long lastBtn1Press = 0;
volatile unsigned long lastBtn2Press = 0;

enum AppState {
  MENU,
  CITIRE,
  SCRIERE_MENU,
  COPIERE,
  SCRIERE_NOU,
  VIEW_LOGS
};

AppState currentState = MENU;
int menuIndex = 0;
int scriereMenuIndex = 0;

void btn1Handler() {
  unsigned long now = millis();
  if (now - lastBtn1Press > DEBOUNCE_MS) {
    lastBtn1Press = now;
    btn1Pressed = true;
  }
}

void btn2Handler() {
  unsigned long now = millis();
  if (now - lastBtn2Press > DEBOUNCE_MS) {
    lastBtn2Press = now;
    btn2Pressed = true;
  }
}

void saveUIDToEEPROM(byte* uid) {
  byte index = EEPROM.read(EEPROM_INDEX_ADDR);
  if (index >= MAX_UIDS) index = 0;

  int addr = EEPROM_LOG_START + index * 7; // 4 uid + 3 time
  for (byte i = 0; i < UID_SIZE; i++) {
    EEPROM.write(addr + i, uid[i]);
  }

  DateTime now = rtc.now();
  EEPROM.write(addr + 4, now.hour());
  EEPROM.write(addr + 5, now.minute());
  EEPROM.write(addr + 6, now.second());

  index = (index + 1) % MAX_UIDS;
  EEPROM.write(EEPROM_INDEX_ADDR, index);
}


void readUIDFromEEPROM(byte* uid, byte* timeBuf, byte slot) {
  int addr = EEPROM_LOG_START + slot * 7;
  for (byte i = 0; i < UID_SIZE; i++) {
    uid[i] = EEPROM.read(addr + i);
  }
  for (byte i = 0; i < 3; i++) {
    timeBuf[i] = EEPROM.read(addr + 4 + i);
  }
}


void showMenu() {
  lcd.clear();
  if (currentState == MENU) {
    const char* optiuni[] = {"Citire", "Scriere", "View Logs"};
    lcd.setCursor(0, 0);
    lcd.print("Meniu:");
    lcd.setCursor(0, 1);
    lcd.print(optiuni[menuIndex]);
  } else if (currentState == SCRIERE_MENU) {
    const char* optiuni[] = {"Copiere", "Scriere noua"};
    lcd.setCursor(0, 0);
    lcd.print("Scriere:");
    lcd.setCursor(0, 1);
    lcd.print(optiuni[scriereMenuIndex]);
  }
}


void citireCarduri() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Scanare card...");

  while (true) {
    if (btn2Pressed) {
      btn2Pressed = false;

      // Întreabă dacă ești admin
      lcd.clear();
      lcd.setCursor(0, 0);
      lcd.print("Esti admin?");
      lcd.setCursor(0, 1);
      lcd.print("Apropie card");

      // Așteaptă un card nou
      while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial());

      // Verifică UID-ul
      String uidStr = "";
      for (byte i = 0; i < mfrc522.uid.size; i++) {
        uidStr += (mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
        uidStr += String(mfrc522.uid.uidByte[i], HEX);
      }

      mfrc522.PICC_HaltA();
      mfrc522.PCD_StopCrypto1();

      if (uidStr == "62787441") {
        lcd.clear();
        lcd.setCursor(0, 0);
        lcd.print("Autentificare OK");
        delay(1500);
        currentState = MENU;
        showMenu();
        return;
      } else {
        lcd.clear();
        lcd.setCursor(0, 0);
        lcd.print("Nu esti admin!");
        delay(2000);
        lcd.clear();
        lcd.setCursor(0, 0);
        lcd.print("Scanare card...");
        continue;
      }
    }

    if (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) continue;

    MFRC522::MIFARE_Key key;
    for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

    byte data[18];
    byte len = 18;
    bool permis = false;
    char nume[17] = "";

    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 4, &key, &(mfrc522.uid)) == MFRC522::STATUS_OK) {
      if (mfrc522.MIFARE_Read(4, data, &len) == MFRC522::STATUS_OK) {
        permis = (data[0] == 'O' && data[1] == 'K');
      }
    }

    if (permis) {
      byte nameBuf[32] = {0};
      for (byte block = 5; block <= 6; block++) {
        if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid)) == MFRC522::STATUS_OK) {
          mfrc522.MIFARE_Read(block, &nameBuf[(block - 5) * 16], &len);
        }
      }
      strncpy(nume, (char*)nameBuf, 16);
    }

    String uidStr = "";
    for (byte i = 0; i < mfrc522.uid.size; i++) {
      uidStr += (mfrc522.uid.uidByte[i] < 0x10 ? "0" : "");
      uidStr += String(mfrc522.uid.uidByte[i], HEX);
    }

    saveUIDToEEPROM(mfrc522.uid.uidByte);

    lcd.clear();
    lcd.setCursor(0, 0);
    if (permis) {
      lcd.print("  Acces permis");
      lcd.setCursor(0, 1);
      lcd.print("  User: ");
      lcd.print(nume);
    } else {
      lcd.print("Acces respins");
      lcd.setCursor(0, 1);
      lcd.print(uidStr.substring(0, 16));
    }

    mfrc522.PICC_HaltA();
    mfrc522.PCD_StopCrypto1();

    delay(3000);
    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("Apropie un card");
  }
}

// Functia de scriere noua: scrie in blocul 4 si numele (max 7 caractere) in blocurile 5 si 6
void scriereNou() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Introduceti user-ul:");

  char nume[8] = {'A', 'A', 'A', 'A', 'A', 'A', 'A', '\0'};
  int poz = 0;
  bool confirmat = false;

  while (!confirmat) {
    lcd.setCursor(0, 1);
    lcd.print(nume);
    lcd.setCursor(poz, 1);
    lcd.blink();

    if (btn1Pressed) { // Schimba litera
      btn1Pressed = false;
      if (nume[poz] == 'Z') nume[poz] = 'A';
      else nume[poz]++;
    }
    if (btn2Pressed) { // Treci la litera urmatoare
      btn2Pressed = false;
      poz++;
      if (poz >= 7) confirmat = true;
    }
    delay(150);
  }
  lcd.noBlink();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Apropie card...");
  while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial());

  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  // Scrie "OK" in blocul 4
  byte bufferOK[16] = {0};
  bufferOK[0] = 'O'; bufferOK[1] = 'K';

  if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 4, &key, &(mfrc522.uid)) != MFRC522::STATUS_OK ||
      mfrc522.MIFARE_Write(4, bufferOK, 16) != MFRC522::STATUS_OK) {
    lcd.clear();
    lcd.print("Eroare scriere OK");
    delay(2000);
    return;
  }

  // Scrie numele in blocurile 5 si 6
  byte nameBuffer[32] = {0};
  memcpy(nameBuffer, nume, 7);

  for (byte block = 5; block <= 6; block++) {
    if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, block, &key, &(mfrc522.uid)) != MFRC522::STATUS_OK ||
        mfrc522.MIFARE_Write(block, &nameBuffer[(block - 5) * 16], 16) != MFRC522::STATUS_OK) {
      lcd.clear();
      lcd.print("Eroare scriere nume");
      delay(2000);
      return;
    }
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Scriere completa");
  delay(2000);
}


// void scriereNou() {
//   lcd.clear();
//   lcd.setCursor(0, 0);
//   lcd.print("Scrie in");
//   lcd.setCursor(0, 1);
//   lcd.print("bloc 4...");

//   while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial());

//   MFRC522::MIFARE_Key key;
//   for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

//   byte buffer[16];
//   for (int i = 0; i < 16; i++) buffer[i] = 0;
//   buffer[0] = 'O';
//   buffer[1] = 'M';

//   if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 4, &key, &(mfrc522.uid)) != MFRC522::STATUS_OK) {
//     lcd.clear();
//     lcd.setCursor(0, 0);
//     lcd.print("Auth error");
//     delay(2000);
//     return;
//   }

//   if (mfrc522.MIFARE_Write(4, buffer, 16) != MFRC522::STATUS_OK) {
//     lcd.clear();
//     lcd.setCursor(0, 0);
//     lcd.print("Write error");
//     delay(2000);
//     return;
//   }

//   mfrc522.PICC_HaltA();
//   mfrc522.PCD_StopCrypto1();

//   lcd.clear();
//   lcd.setCursor(0, 0);
//   lcd.print("Scriere completa");
//   delay(2000);
// }


// Fct de copiere card
void copieCard() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print(" Apropie cardul");
  lcd.setCursor(0, 1);
  lcd.print("   sursa...");

  while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial());

  MFRC522::MIFARE_Key key;
  for (byte i = 0; i < 6; i++) key.keyByte[i] = 0xFF;

  byte buffer[16];
  byte len = 18;

  if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 4, &key, &(mfrc522.uid)) != MFRC522::STATUS_OK ||
      mfrc522.MIFARE_Read(4, buffer, &len) != MFRC522::STATUS_OK) {
    lcd.clear();
    lcd.print("Eroare citire src");
    delay(2000);
    return;
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Destinatie card");
  lcd.setCursor(0, 1);
  lcd.print("Apropie-l acum");

  while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial());

  if (mfrc522.PCD_Authenticate(MFRC522::PICC_CMD_MF_AUTH_KEY_A, 4, &key, &(mfrc522.uid)) != MFRC522::STATUS_OK ||
      mfrc522.MIFARE_Write(4, buffer, 16) != MFRC522::STATUS_OK) {
    lcd.clear();
    lcd.print("Eroare scriere dst");
    delay(2000);
    return;
  }

  mfrc522.PICC_HaltA();
  mfrc522.PCD_StopCrypto1();

  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Acces copiat");
  delay(2000);
}


void viewLogs() {
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("Ultimele carduri");
  delay(1500);
  lcd.clear();

  for (int i = 0; i < MAX_UIDS; i++) {
    byte uid[UID_SIZE];
    byte timeBuf[3];
    readUIDFromEEPROM(uid, timeBuf, i);

    String uidStr = "";
    for (byte j = 0; j < UID_SIZE; j++) {
      uidStr += (uid[j] < 0x10 ? "0" : "");
      uidStr += String(uid[j], HEX);
    }

    char timp[9];
    sprintf(timp, "%02d:%02d:%02d", timeBuf[0], timeBuf[1], timeBuf[2]);

    lcd.clear();
    lcd.setCursor(0, 0);
    lcd.print("Log ");
    lcd.print(i + 1);
    lcd.print(": ");
    lcd.print(timp);
    lcd.setCursor(0, 1);
    lcd.print(uidStr);
    delay(2000);
  }

  currentState = MENU;
  showMenu();
}




void setup() {
  Serial.begin(9600);
  SPI.begin();
  mfrc522.PCD_Init();

  lcd.init();
  lcd.backlight();

  pinMode(BUTTON1_PIN, INPUT_PULLUP);
  pinMode(BUTTON2_PIN, INPUT_PULLUP);

  attachInterrupt(digitalPinToInterrupt(BUTTON1_PIN), btn1Handler, FALLING);
  attachInterrupt(digitalPinToInterrupt(BUTTON2_PIN), btn2Handler, FALLING);

  if (!rtc.begin()) {
    lcd.clear();
    lcd.print("RTC absent!");
    while (1); // Blochează execuția
  }

  lcd.setCursor(0, 0);
  lcd.print("SmartAccess");
  lcd.setCursor(0, 1);
  lcd.print("Marius' Project");
  delay(2000);
  showMenu();
}

void loop() {
  if (btn1Pressed) {
    btn1Pressed = false;
    if (currentState == MENU) {
      menuIndex = (menuIndex + 1) % 3;
      showMenu();
    } else if (currentState == SCRIERE_MENU) {
      scriereMenuIndex = (scriereMenuIndex + 1) % 2;
      showMenu();
    }
  }

  if (btn2Pressed) {
    btn2Pressed = false;
    if (currentState == MENU) {
      if (menuIndex == 0) {
        currentState = CITIRE;
        citireCarduri();
      } else if (menuIndex == 1) {
        currentState = SCRIERE_MENU;
        showMenu();
      } else if (menuIndex == 2) {
        currentState = VIEW_LOGS;
        viewLogs();
      }
    } else if (currentState == SCRIERE_MENU) {
      if (scriereMenuIndex == 0) {
        currentState = COPIERE;
        copieCard();
        currentState = MENU;
        showMenu();
      } else if (scriereMenuIndex == 1) {
        currentState = SCRIERE_NOU;
        scriereNou();
        currentState = MENU;
        showMenu();
      }
    }
  }
}
