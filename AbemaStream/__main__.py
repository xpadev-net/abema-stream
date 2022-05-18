from . import AbemaStream
import argparse

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Download stream from abema')
    parser.add_argument('channel', help='channel to download')
    parser.add_argument('output_dir', help='folder to save videos')
    parser.add_argument('--tmp-dir', help='folder to save temporary files')
    parser.add_argument('--target', help='download only the stream with the specified id')
    parser.add_argument('--log-level', help='set log level', default="DEBUG",
                        choices=["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"])
    args = parser.parse_args()
    abemaStream = AbemaStream(channel=args.channel, output_dir=args.output_dir, temp_dir=args.tmp_dir,
                              target=args.target, log_level=args.log_level)
