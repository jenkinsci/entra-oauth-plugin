package io.jenkins.plugins.entraoauth;

final class PemFixtures {
    private PemFixtures() {}

    static final String CERT_PEM = """
            -----BEGIN CERTIFICATE-----
            MIIBszCCAVmgAwIBAgIJAOA4Q2c9x/2mMAoGCCqGSM49BAMCMBMxETAPBgNVBAMM
            CHRlc3QtY2VydDAeFw0yMDAxMDEwMDAwMDBaFw0zMDAxMDEwMDAwMDBaMBMxETAP
            BgNVBAMMCHRlc3QtY2VydDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLdK6S6T
            6q2bM4X9+X7QnH2f9/2M6qlL6q6q0p9E3e3hJ+E7sPjCz2K1O7r8T3FJ8M0c9R1f
            XWf2H2FQmyGjUDBOMB0GA1UdDgQWBBSmX9Y8G7s7tq1T6YwXq1t6g7dJzzAfBgNV
            HSMEGDAWgBSmX9Y8G7s7tq1T6YwXq1t6g7dJzzAMBgNVHRMEBTADAQH/MAoGCCqG
            SM49BAMCA0gAMEUCIQDvYhXf0k6glx4wK6n+9kSxQw9m8vQ8v1q8X2m3Y8t1vQIg
            bSxg9x6Hn8Zf7F7k0c2kq9C2GQ3m1t8V8p8tZ6k=
            -----END CERTIFICATE-----""";

    static final String KEY_PEM = """
            -----BEGIN PRIVATE KEY-----
            MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg6Q2b7WnWQy2i3g0E
            fX9d9gOQ0b2Wv6F8mT0w1nuhRANCAAS3Sukuk+qtmzOF/fl+0Jx9n/f9jOqpS+qu
            qtKfRN3t4SfhO7D4ws9itTu6/E9xSfDNHPUdX11n9h9hUJs=
            -----END PRIVATE KEY-----""";
}


