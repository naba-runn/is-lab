def function(s):

    one = zero = 0

    for c in s:
        if c == "0":
            zero += 1
        else:
            one += 1

    prev = 0
    res = ""

    while zero > 0 and one > 0:
        if prev == 0:
            res = "1" + res
            one -= 1
            prev = 1
        else:
            res = "0" + res
            zero -= 1
            prev = 0

    while zero > 0:
        res = "0" + res
        zero -= 1

    while one > 0:
        res = "1" + res
        one -= 1

    return res


def main():
    s = input("Enter binary string: ")
    print("Answer:", function(s))


if __name__ == "__main__":
    main()