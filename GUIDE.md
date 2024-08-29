# OT Registrar Guide

## Setup

All setup commands assume you are starting in the project's root directory.

1. Bootstrap

    Install the required packages ([java](https://openjdk.java.net/), [maven](https://maven.apache.org/)):

    ```bash
    ./script/bootstrap.sh
    ```

2. Build

    Build and run unit tests for the OT Registrar JAR package:

    ```bash
    mvn package
    ```

    Or, to skip the tests:

    ```bash
    mvn -DskipTests package
    ```

    Either of these creates a JAR file at `target/ot-registrar-0.3-jar-with-dependencies.jar`.

## Run services

The OT Registrar JAR file includes the Registrar, MASA server, and a simulated Pledge. These 3 components are sufficient to do a test run of the system.

### Credentials

To run the registrar or MASA server, we need a structured keystore file (in PKCS#12 format) containing the credentials.

Details on how to generate credentials will be added at a later time. For this guide, we'll use 
credentials provided with OT Registrar in the `credentials` directory.

### Run the registrar

Start the registrar at default CoAPS port 5684, using the default credentials:

```bash
$ ./script/run -registrar
```

Use the `-h` option to learn what arguments are available:

```text
$ ./script/run -h
usage: [-registrar | -masa | -pledge] [-h] [-v] [-d <domain-name>] [-f
                   <keystore-file>] [-p <udp-port>]
 -d,--domainname <domain-name>       the domain name
 -f,--keyfile <keystore-file>        the keystore file in PKCS#12 format
 -h,--help                           print this message
 -m,--masaUri <forced-masa-uri>      force the given MASA URI instead of
                                     the default one
 -masa                               start as cBRSKI/BRSKI MASA
 -p,--port <server-port>             the server CoAPS or HTTPS port to
                                     listen on
 -pledge                             start as cBRSKI Pledge
 -r,--registrarUri <registrar-uri>   for a Pledge, the Registrar to
                                     connect to
 -registrar                          start as cBRSKI Registrar
 -v,--verbose                        verbose mode with many logs
```

### Run the MASA server

Start the MASA server in another window or tab at port 9443, using the default credentials:

```bash
$ ./script/run -masa -p 9443
...
```

### Run the pledge

Use a simulated pledge to test the Registrar.

Start the pledge in another shell window or tab, connecting to a specific host and port where the Registrar is expected:

```bash
$ ./script/run -pledge -r "[::1]:5684"
...
```

The pledge enters interactive mode and waits for user commands. Press **Enter** or type `help` to get a list of all available commands:

```text
> help
rv       -  request voucher to Registrar (cBRSKI)
enroll   -  simple enrollment with Registrar (EST)
reenroll -  simple reenrollment with Registrar (EST)
reset    -  reset Pledge to initial state
exit     -  exit pledge CLI
help     -  print this help message
Done
>
```

Use the `exit` command to exit or **Ctrl+c** to force exit.

Use `rv` to let the Pledge attempt a cBRSKI Voucher Request:

```text
> rv
19:30:24.606 [DTLS-Connection-Handler-5] INFO com.google.openthread.pledge.PledgeCertificateVerifier - registrar provisionally accepted without verification!
Done
```

Now the Voucher is obtained from MASA, via the Registrar. Mutual trust is established for the active DTLS connection. Use `enroll` to perform the EST-CoAPS enrollment:

```text
> enroll
19:34:58.825 [main] INFO com.google.openthread.pledge.Pledge - enrolled with operational certificate, subject: C=US,ST=CA,L=San Ramon,O=TestVendor,2.5.4.5=#130a41383544333330303031,CN=TestVendor IoT device
19:34:58.827 [main] INFO com.google.openthread.pledge.Pledge - operational certificate (PEM): 
-----BEGIN CERTIFICATE-----
MIICEDCCAbegAwIBAgIBAzAKBggqhkjOPQQDAjBTMREwDwYDVQQDDAhkb21haW5j
YTETMBEGA1UECwwKT3BlblRocmVhZDEPMA0GA1UECgwGR29vZ2xlMQswCQYDVQQH
DAJTSDELMAkGA1UEBhMCQ04wHhcNMjQwODI4MTkzNDU4WhcNMjkwODI3MTkzNDU4
WjB4MR4wHAYDVQQDDBVUZXN0VmVuZG9yIElvVCBkZXZpY2UxEzARBgNVBAUTCkE4
NUQzMzAwMDExEzARBgNVBAoMClRlc3RWZW5kb3IxEjAQBgNVBAcMCVNhbiBSYW1v
bjELMAkGA1UECAwCQ0ExCzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEGwAmAr657PJ63qBg2axjNTK0FhT0pI11qn5mUq6TQFF6RjU22zqqbJZl
a7EbDmVRouS+6jIM/8yycqE2NrwQ3aNXMFUwCQYDVR0TBAIwADAfBgNVHSMEGDAW
gBSe2sIzlf9yKOt9rsh9GC356FdvVzAnBgNVHREEIDAeoBwGCSsGAQQBgt8qAaAP
Fg1EZWZhdWx0RG9tYWluMAoGCCqGSM49BAMCA0cAMEQCIDD63H5wYJVvo+sKgt3S
U38XMON3cYz/5KlF1PmxnmJjAiBKujydxak63+L2aZB/H3YoYq0M53xRQMRUGRku
75pjeg==
-----END CERTIFICATE-----

19:34:58.829 [main] INFO com.google.openthread.pledge.Pledge - operational private key (PEM): 
-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIPPqdOhhBgm/RdVsd4SVQ2g3/U4KVC2mtP2RzCbgL0oNoAoGCCqGSM49
AwEHoUQDQgAEGwAmAr657PJ63qBg2axjNTK0FhT0pI11qn5mUq6TQFF6RjU22zqq
bJZla7EbDmVRouS+6jIM/8yycqE2NrwQ3Q==
-----END EC PRIVATE KEY-----

Done
```

## The Docker service

You can use `script/run-servers.sh` to run both Registrar and MASA on the local host. To avoid having to frequently start and stop servers, OT Registrar provides a Docker image to start all services with a single command.

_**Note:** Only supported on Linux._

1. Do the bootstrap script if you haven't already.

2. Build the Docker image:

    ```bash
    ./script/build-docker-image.sh
    ```

3. Start all services in a Docker:

    ```bash
    ./script/start-service.sh
    ```
