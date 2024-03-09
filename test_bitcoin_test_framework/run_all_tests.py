import test_p2pk
import test_p2ms


if __name__ == "__main__":
    try:
        test_p2pk.P2PKTest().main()
    except Exception as e:
        print(f"Error in P2PKTest: {e}")

    print("Hallo")

    #try:
    #    test_p2ms.P2MSTest().main()
    #except Exception as e:
    #    print(f"Error in P2MSTest: {e}")