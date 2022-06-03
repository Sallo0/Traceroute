import argparse

import Traceroute


def main():
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("address", type=str, help="The address to traceroute")
    argument_parser.add_argument(
        "-r", "--requests", type=int, default=3, help="Quantity of requests on every step. Default is 3"
    )
    argument_parser.add_argument(
        "-w", "--wait", type=float, default=0, help="Minimal time between requests in s. Default is 0"
    )
    argument_parser.add_argument(
        "-t", "--timeout", type=float, default=2, help="Maximal time to receive response in s. Default is 2"
    )
    argument_parser.add_argument(
        "-m", "--maxttl", type=int, default=30, help="Max steps to desired address. Default is 30"
    )
    argument_parser.add_argument(
        "-d", "--datasize", type=int, default=40, help="Size of request packet (bytes). Default is 40"
    )

    argument_parser.add_argument("-p", "--port", type=int, default=0, help="Port for TCP request")

    args = argument_parser.parse_args()
    try:
        Traceroute.traceroute(
            args.address, args.requests, args.wait, args.timeout, args.maxttl, args.datasize, args.port
        )
    except PermissionError as e:
        print(e, "Permission denied")


if __name__ == "__main__":
    main()
