import argparse
from AndroguardProject.androguardStarter import invokeAndroguard


def analyze(path_to_apk):

    a, d, dx = invokeAndroguard(path_to_apk)

    print a.get_app_name()


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description="Test permission analysis")

    parser.add_argument("-i", "--input",
                        required=True, help="Path to apk file")
    args = parser.parse_args()

    analyze(args.input)