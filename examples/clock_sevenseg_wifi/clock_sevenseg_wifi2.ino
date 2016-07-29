// Clock example using a seven segment display & NTP clock synchronization
//
// Designed specifically to work with the Adafruit LED 7-Segment backpacks
// and the Feather M0 WIFI and Arduino Zero with WIFI1500 shield.
//
// Adafruit invests time and resources providing this open source code,
// please support Adafruit and open-source hardware by purchasing
// products from Adafruit!
//
// Based on clock_sevenseg_DS1307 written by Tony DiCola for Adafruit Industries.
//
// Modified for NTP and WINC1500 by Rick Lesniak for Adafruit Industries
//
// Released under a MIT license: https://opensource.org/licenses/MIT

#include <Wire.h>
#include "Adafruit_LEDBackpack.h"
#include "Adafruit_GFX.h"

#include "TimeLib.h"

#include <SPI.h>
#include <Adafruit_WINC1500.h>
#include <Adafruit_WINC1500Udp.h>

// Set to false to display time in 12 hour format, or true to use 24 hour:
#define TIME_24_HOUR      true
#define NTP_SYNC_INTERVAL 86400  /*M0 clock apparently drifts a bit.  re-sync every day */

// I2C address of the display.  Stick with the default address of 0x70
// unless you've changed the address jumpers on the back of the display.
#define DISPLAY_ADDRESS   0x70


// Create display object.  This is a global variable that
// can be accessed from both the setup and loop function below.
Adafruit_7segment clockDisplay = Adafruit_7segment();

int hours = 0;
int minutes = 0;
int seconds = 0;
int tzOffset = -4;     // Time zone offset: -4 is Eastern Daylight Time.  change to -5 for Eastern Standard Time

// Remember if the colon was drawn on the display so it can be blinked
// on and off every second.
bool blinkColon = false;

// Define the WINC1500 board connections below.
// If you're following the Adafruit WINC1500 board
// guide you don't need to modify these:
#define WINC_CS   8
#define WINC_IRQ  7
#define WINC_RST  4
#define WINC_EN   2     // or, tie EN to VCC and comment this out

// The SPI pins of the WINC1500 (SCK, MOSI, MISO) should be
// connected to the hardware SPI port of the Arduino.
// On an Uno or compatible these are SCK = #13, MISO = #12, MOSI = #11.
// On an Arduino Zero use the 6-pin ICSP header, see:
//   https://www.arduino.cc/en/Reference/SPI

// For WiFI Feather, setup the WINC1500 connection with the pins above 
//  and the default hardware SPI.
Adafruit_WINC1500 WiFi(WINC_CS, WINC_IRQ, WINC_RST);

// For WiFi1500 shield, use hardware SPI (SCK/MOSI/MISO) and defaults, 
//    SS -> #10, INT -> #7, RST -> #5, EN -> 3-5V
//Adafruit_WINC1500 WiFi;

int status = WL_IDLE_STATUS;
char ssid[] = "xxxx";  //  your network SSID (name)
char pass[] = "xxxx";       // your network password
int keyIndex = 0;            // your network key Index number (needed only for WEP)

unsigned int localPort = 2390;      // local port to listen for UDP packets

/* Don't hardwire the IP address or we won't get the benefits of the pool.
    Lookup the IP address for the host name instead */
IPAddress timeServerIP; // NTP server IP address
const char* ntpServerName = "us.pool.ntp.org";  //change to match your own regional pool

const int NTP_PACKET_SIZE = 48; // NTP time stamp is in the first 48 bytes of the message

byte packetBuffer[NTP_PACKET_SIZE]; //buffer to hold incoming and outgoing packets

// A UDP instance to let us send and receive packets over UDP
Adafruit_WINC1500UDP Udp;

//Forward declarations
time_t getNTPTime();
unsigned long sendNTPpacket(IPAddress& address);
void printWifiStatus();
void printOledData();

void setup() {
#ifdef WINC_EN
  pinMode(WINC_EN, OUTPUT);
  digitalWrite(WINC_EN, HIGH);
#endif

//  while (!Serial);
  // Setup Serial port to print debug output.
  Serial.begin(9600);
  Serial.println("Clock starting!");

  // check for the presence of the shield:
  if (WiFi.status() == WL_NO_SHIELD) {
    Serial.println("WiFi shield not present");
    // don't continue:
    while (true);
  }

  // attempt to connect to Wifi network:
  while ( status != WL_CONNECTED) {
    Serial.print("Attempting to connect to SSID: ");
    Serial.println(ssid);
    // Connect to WPA/WPA2 network. Change this line if using open or WEP network:
    status = WiFi.begin(ssid, pass);

    // wait 10 seconds for connection:
    delay(10000);
  }

  Serial.println("Connected to wifi");
  printWifiStatus();

  Serial.println("\nStarting connection to server...");
  Udp.begin(localPort);

  // Setup the LED display.
  clockDisplay.begin(DISPLAY_ADDRESS);

  //Set up NTP Time callback
  setSyncInterval(NTP_SYNC_INTERVAL);   //sync to NTP this often
  setSyncProvider(getNTPTime);

  Serial.println("Waiting for NTP sync");
  //wait for initial time sync to succeed.  getNTPTime will reset the sync interval to 15 seconds if NTP fails
  while (timeSet != timeStatus())
  {
    Serial.println("Waiting for NTP sync");
    time_t timenow = now();
    delay(1000);
  }
  Serial.println("NTP time is set");    //sync interval automatically reset to 1 day

//setTime(1468987185);  //set clock to 15 seconds before midnight for debugging purposes.

  Serial.println("start ticking");
}

void loop() {
  uint32_t loopStart = millis();
  // Loop function runs over and over again to implement the clock logic.

  time_t timenow = now();
  hours = hour(timenow);
  minutes = minute(timenow);
  seconds = second(timenow);

  //time zone adustment. NTP time is UTC
  hours = hours + tzOffset;
  if (hours < 0)  //handle wraparound
    hours = hours + 24;
  else
  {
    if (hours > 23)
      hours = hours - 24;
  }

  // Show the time on the display by turning it into a numeric
  // value, like 3:30 turns into 330, by multiplying the hour by
  // 100 and then adding the minutes.
  int displayValue = hours * 100 + minutes;

  // Do 24 hour to 12 hour format conversion when required.
  if (!TIME_24_HOUR) {
    // Handle when hours are past 12 by subtracting 12 hours (1200 value).
    if (hours > 12) {
      displayValue -= 1200;
    }
    // Handle hour 0 (midnight) being shown as 12.
    else if (hours == 0) {
      displayValue += 1200;
    }
  }

  // Now print the time value to the display.
  clockDisplay.print(displayValue, DEC);

  // Add zero padding when in 24 hour mode and it's midnight.
  // In this case the print function above won't have leading 0's
  // which can look confusing.  Go in and explicitly add these zeros.
  if (TIME_24_HOUR && hours == 0) {
    // Pad hour 0.
    clockDisplay.writeDigitNum(1, 0);
   // Also pad when the 10's minute is 0 and should be padded.
   if (minutes < 10) {
     clockDisplay.writeDigitNum(3, 0);
   }
 }
  
  // Blink the colon by flipping its value every loop iteration
  // (which happens every second).
  blinkColon = !blinkColon;
  clockDisplay.drawColon(blinkColon);

  // Now push out to the display the new values that were set above.
  clockDisplay.writeDisplay();

  // Pause for a second for time to elapse.  This value is in milliseconds
  // so 1000 milliseconds = 1 second.
  delay(1000 - (millis() - loopStart));  //compensate for the time we spent in loop
}

time_t getNTPTime()
{
  time_t epoch = 0;
  int retries = 0;

  //get a random server from the pool
  WiFi.hostByName(ntpServerName, timeServerIP);

  sendNTPpacket(timeServerIP); // send an NTP packet to a time server
  // wait to see if a reply is available
  int replyLen;
  do {
    delay(1000);
    replyLen = Udp.parsePacket();
  } while ((retries++ < 15) && (!replyLen));

  if (!replyLen) {  //run out of retries?
    Serial.println("no packet yet");
    setSyncInterval(30);   //try again in a few seconds
  }
  else
  {
    Serial.println("packet received");
    setSyncInterval(NTP_SYNC_INTERVAL);
    // We've received a packet, read the data from it
    Udp.read(packetBuffer, NTP_PACKET_SIZE); // read the packet into the buffer

    //the timestamp starts at byte 40 of the received packet and is four bytes,
    // or two words, long. First, esxtract the two words:

    unsigned long highWord = word(packetBuffer[40], packetBuffer[41]);
    unsigned long lowWord = word(packetBuffer[42], packetBuffer[43]);
    // combine the four bytes (two words) into a long integer
    // this is NTP time (seconds since Jan 1 1900):
    unsigned long secsSince1900 = highWord << 16 | lowWord;
    Serial.print("Seconds since Jan 1 1900 = " );
    Serial.println(secsSince1900);

    // now convert NTP time into everyday time:
    Serial.print("Unix time = ");
    // Unix time starts on Jan 1 1970. In seconds, that's 2208988800:
    const unsigned long seventyYears = 2208988800UL;
    // subtract seventy years:
    epoch = secsSince1900 - seventyYears;
    Serial.println(epoch);
  }
  return epoch;
}

// send an NTP request to the time server at the given address
unsigned long sendNTPpacket(IPAddress & address)
{
  //Serial.println("1");
  // set all bytes in the buffer to 0
  memset(packetBuffer, 0, NTP_PACKET_SIZE);
  // Initialize values needed to form NTP request
  // (see URL above for details on the packets)
  //Serial.println("2");
  packetBuffer[0] = 0b11100011;   // LI, Version, Mode
  packetBuffer[1] = 0;     // Stratum, or type of clock
  packetBuffer[2] = 6;     // Polling Interval
  packetBuffer[3] = 0xEC;  // Peer Clock Precision
  // 8 bytes of zero for Root Delay & Root Dispersion
  packetBuffer[12]  = 49;
  packetBuffer[13]  = 0x4E;
  packetBuffer[14]  = 49;
  packetBuffer[15]  = 52;

  //Serial.println("3");

  // all NTP fields have been given values, now
  // you can send a packet requesting a timestamp:
  Udp.beginPacket(address, 123); //NTP requests are to port 123
  //Serial.println("4");
  Udp.write(packetBuffer, NTP_PACKET_SIZE);
  //Serial.println("5");
  Udp.endPacket();
  //Serial.println("6");
}


void printWifiStatus() {
  // print the SSID of the network you're attached to:
  Serial.print("SSID: ");
  Serial.println(WiFi.SSID());

  // print your WiFi shield's IP address:
  IPAddress ip = WiFi.localIP();
  Serial.print("IP Address: ");
  Serial.println(ip);

  // print the received signal strength:
  long rssi = WiFi.RSSI();
  Serial.print("signal strength (RSSI):");
  Serial.print(rssi);
  Serial.println(" dBm");
}

