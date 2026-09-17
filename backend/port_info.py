import subprocess


def main():
    targets = [
        "10.0.2.2",
        "10.0.2.3",
        "10.0.2.15"
    ]

    command = [
        "nmap",
        "--privileged",
        "-sS",
        "-sV",
        "--version-intensity",
        "9",
        "-T3",
        "-Pn",
        "--top-ports",
        "1000",
        "-oX",
        "-"
    ] + targets

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    print(result.stdout, end="")

    if result.stderr:
        print(result.stderr, end="")


if __name__ == "__main__":
    main()
