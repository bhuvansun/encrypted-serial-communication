#include <SoftwareSerial.h>
#include <HardwareSerial.h>
#include <Arduino.h>
#include <uECC.h>
#include <uECC_vli.h>

#ifndef __SECURE_SERIAL_H__
#define __SECURE_SERIAL_H__

#define DEBUG
#ifdef DEBUG
#define LOG_START_S(X) Serial.print("[DEBUG BEGIN] FN:"); Serial.println(X);
#define LOG_END_S(X) Serial.print("[DEBUG END] FN:"); Serial.println(X);
#else 
#define LOG_START_S(X)
#define LOG_END_S(X)
#endif

#define LOG_START LOG_START_S(__func__);
#define LOG_END LOG_END_S(__func__);

#define DELAYUS delayMicroseconds(100);
#define COOLDOWN delay(500);

#define RECV recv_line(cmd, CMDLEN);
#define COMP(X) strncmp(cmd, X, CMDLEN)
#define WAIT(X) while (COMP(X)) {RECV; COOLDOWN;}
extern HardwareSerial Serial;

#define CMDLEN 5
#define CMDMSG "MESS\n"
#define CMDHELLO1 "HEL1\n"
#define CMDHELLO2 "HEL2\n"
#define CMDRECP "PUBL\n"
#define CMDRECA "PUBA\n"
#define key_size 32

class secure_serial {
    SoftwareSerial* serial;
    uECC_Curve curve;

    char cmd[CMDLEN];

    bool first = false;
    uint8_t private_key[key_size];
    uint8_t public_key[key_size * 2];
    uint8_t shared_secret[key_size];

    void recv_line(char* dst, int maxlen);

    // Hello
    void send_hello();
    void send_hello2();

    // Send and receive public keys
    void send_pub_key();
    void recv_pub_key();
public:
    void begin(uint8_t RX, uint8_t T, bool first_device);

    void send_from_serial();
    void recv_to_serial();
    void send(const char* message);
    int available();
    void initial_sequence();

    // Send encrypted messages
    void send_msg(uint8_t* message, int len);
    void recv_msg(uint8_t* message, int len);

    void set_public_key(const char* key);
    void set_private_key(const char* key);
    void set_shared_secret(const char* secret);
};

#endif