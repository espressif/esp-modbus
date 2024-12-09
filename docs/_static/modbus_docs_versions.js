var DOCUMENTATION_VERSIONS = {
    DEFAULTS: { has_targets: true,
                supported_targets: [ "esp32", "esp32s2", "esp32s3", "esp32c2","esp32c3", "esp32c5", "esp32c6", "esp32c61", "esp32s2", "esp32s3, esp32p4" ]
              },
    VERSIONS: [
        { name: "latest" },
        { name: "v1.0.1", old:true },
        { name: "v2.0.0", old:false }
    ],
    IDF_TARGETS: [
       { text: "ESP32", value: "esp32"},
       { text: "ESP32-S2", value: "esp32s2"},
       { text: "ESP32-S3", value: "esp32s3"},
       { text: "ESP32-C2", value: "esp32c2"},
       { text: "ESP32-C3", value: "esp32c3"},
       { text: "ESP32-C6", value: "esp32c6"},
       { text: "ESP32-H2", value: "esp32h2"},
       { text: "ESP32-P4", value: "esp32p4"},
       { text: "ESP32-C5", value: "esp32c5"},
       { text: "ESP32-C61", value: "esp32c61"}
    ]
};
