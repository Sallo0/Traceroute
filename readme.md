# Traceroute
TCP implementation of traceroute on python.
# Usage

```sh
python  main.py [Flags] IPV4_address
```

# Result 
```
1   ipv4_address1     	time  ms  
2   ipv4_address2       time  ms  
3   *                   *     Превышен интервал ожидания для запрос 
...
```
# Flags
| Flag                             | Description                                         |
|----------------------------------|-----------------------------------------------------|
| -h, --help                       | show help message and exit                          |
| -r REQUESTS, --requests REQUESTS | Quantity of requests on every step. Default is 3    |
| -w WAIT, --wait WAIT             | Minimal time between requests in s. Default is 0    |
| -t TIMEOUT, --timeout TIMEOUT    | Maximal time to receive response in s. Default is 2 |
| -m MAXTTL, --maxttl MAXTTL       | Max steps to desired address. Default is 30         |
| -d DATASIZE, --datasize DATASIZE | Size of request packet (bytes). Default is 40       |
| -p PORT, --port PORT             | Port for TCP request                                |

