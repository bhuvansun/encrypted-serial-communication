#include "uECC.h"
#include "secure_serial.h"

static int random_uECC(uint8_t *dest, unsigned size) {
  while (size) {
    uint8_t val = 0;
    for (unsigned i = 0; i < 8; ++i) {
        int init = analogRead(0);
        int count = 0;
        while (analogRead(0) == init) ++count;
        if (!count) val = (val << 1) | (init & 0x01);
        else val = (val << 1) | (count & 0x01);
    }

    *dest = val;
    ++dest;
    --size;
  }

  return 1;
}

void print_array(uint8_t* arr, int len) {
    for (int i=0; i<len; ++i) {
        Serial.print(arr[i]);
        Serial.print(",");
    }
    Serial.println();
}

void secure_serial::begin(uint8_t rx, uint8_t tx, bool first_device) {
    LOG_START
    serial = new SoftwareSerial(rx, tx);
    curve = uECC_secp256r1();
    first = first_device;

    pinMode(rx, INPUT);
    pinMode(tx, OUTPUT);

    serial->begin(115200);
    while (!(*serial));

    uECC_set_rng(&random_uECC);
    uECC_make_key(public_key, private_key, curve);

    print_array(public_key, key_size * 2);
    print_array(private_key, key_size);
    LOG_END
}

void secure_serial::recv_to_serial() {
    LOG_START

    while (serial->available()) {
        Serial.write((char) serial->read());
    }
    LOG_END
}

void secure_serial::send(const char* msg) {
    LOG_START
    serial->print(msg);
    LOG_END
}

void secure_serial::recv_line(char* dst, int maxlen) {
    int l=0;
    char ch = '\0';
    while (ch != '\n' && l < maxlen) {
        ch = serial->read();
        dst[l++] = ch;
    }
}

void secure_serial::send_from_serial() {
    LOG_START
    while (Serial.available())
        serial->print((char) Serial.read());
    recv_to_serial();
    LOG_END
}

int secure_serial::available() {
    return serial->available();
}

void secure_serial::recv_pub_key() {
    LOG_START
    send(CMDRECP);
    WAIT(CMDRECA);

    uint8_t recv_pub_key[key_size * 2];
    uint8_t sz = serial->readBytes(recv_pub_key, key_size * 2);
#ifdef DEBUG
    Serial.print("[DEBUG] recv:");
    Serial.println(sz);
#endif
    uECC_shared_secret(recv_pub_key, private_key, shared_secret, curve);
    LOG_END
}

void secure_serial::send_hello() {
    LOG_START
    send(CMDHELLO1);
    LOG_END
}

void secure_serial::send_hello2() {
    LOG_START
    send(CMDHELLO2);
    LOG_END
}

void secure_serial::send_pub_key() {
    LOG_START
    send(CMDRECA);
    for (uint8_t i=0; i<key_size; ++i)
        serial->write(public_key[i]);
    if (!first) send(CMDRECP);
    LOG_END
}

void secure_serial::initial_sequence() {
    LOG_START
    if (first) {
        send_hello();
        recv_pub_key();
        WAIT(CMDRECP);
        send_pub_key();
    } else {
        WAIT(CMDHELLO1);
        send_hello2();
        WAIT(CMDRECP);
        send_pub_key();
        recv_pub_key();
    }

    LOG_END
}

void secure_serial::send_msg(uint8_t* message, int len) {
    LOG_START
    send(CMDMSG);
    serial->print(len);
    for (int i = 0; i < len; i++) {
        serial->print((char)(message[i] ^ shared_secret[i%key_size]));
    }
    LOG_END
}

void secure_serial::recv_msg(uint8_t* message, int len) {
    LOG_START
    WAIT(CMDMSG);
    int r = serial->read();
    serial->readBytes(message, r);

    for (int i=0; i<r; ++i) {
        message[i] ^= shared_secret[i % key_size];
    }
    LOG_END
}

void secure_serial::set_public_key(const char *key) {
    memcpy(public_key, key, key_size * 2);
}

void secure_serial::set_private_key(const char *key) {
    memcpy(private_key, key, key_size * 2);
}

void secure_serial::set_shared_secret(const char *secret) {
    memcpy(shared_secret, secret, key_size);
}