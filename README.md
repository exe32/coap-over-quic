# coap-over-quic

## Test notes
Run client:
```
python coap_client_datagrams.py --ca-certs certs/pycacert.pem --remoteQuicHost 127.0.0.1 --remoteQuicPort 4784 --secrets-log secret.key
```

Run server:
```
python coap_server_datagrams.py --certificate certs/ssl_cert.pem --private-key certs/ssl_key.pem --host 127.0.0.1 --verbose
```

Send client data
```
echo -n test | nc -u 127.0.0.1 5683
```

