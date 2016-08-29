# ripple-validator-list

test server that publishes list of Ripple validator keys

```
$ npm install
$ npm start
```

Run `rippled` with the following sections in `rippled.cfg`:

```
[validator_list_sites]
http://localhost:8000

[validator_list_keys]
aKEKiic24cH5kmyhmHLhT6FNGPSLpbtkYJU4f42LHdfC4NxQc3pX
```

```
$ rippled -q unl_list
{
   "result" : {
      "status" : "success",
      "unl" : [
         {
            "pubkey_validator" : "nHB1X37qrniVugfQcuBTAjswphC1drx7QjFFojJPZwKHHnt8kU7v",
            "trusted" : false
         },
         {
            "pubkey_validator" : "nHBu9PTL9dn2GuZtdW4U2WzBwffyX9qsQCd9CNU4Z5YG3PQfViM8",
            "trusted" : false
         },
         {
            "pubkey_validator" : "nHUkAWDR4cB8AgPg7VXMX6et8xRTQb2KJfgv1aBEXozwrawRKgMB",
            "trusted" : false
         },
         {
            "pubkey_validator" : "nHUhG1PgAG8H8myUENypM35JgfqXAKNQvRVVAFDRzJrny5eZN8d5",
            "trusted" : false
         },
         {
            "pubkey_validator" : "nHUPDdcdb2Y5DZAJne4c2iabFuAP3F34xZUgYQT2NH7qfkdapgnz",
            "trusted" : false
         }
      ]
   }
}
```