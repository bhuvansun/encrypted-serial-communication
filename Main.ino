#include "secure_serial.h"
secure_serial bt;

void setup() {
    Serial.begin(115200);
    LOG_START
    bt.begin(2, 3, true);  // 2 -> TXD 3 -> RXD    
    // bt.set_shared_secret(shared_secret);
    bt.initial_sequence();
    LOG_END
}

void loop() {
    bt.send_msg("This is an encrypted message!", 29);
    delay(1000);
    bt.send_from_serial();
}
