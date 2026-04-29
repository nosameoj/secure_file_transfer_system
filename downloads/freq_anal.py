def frequency_analysis(ciphertext):
    freq = {}
    for char in ciphertext:
        if char.isalpha():
            char = char.lower()
            if char in freq:
                freq[char] += 1
            else:
                freq[char] = 1
    sorted_freq = sorted(freq.items(), key=lambda x: x[1], reverse=True)
    return sorted_freq

if __name__ == "__main__":
    print("Welcome to the Frequency analysis program")
    ciphertext = str(input("Enter the cipher text"))

    analysis_results = frequency_analysis(ciphertext)
    print("Results:")
    for letter, count in analysis_results:
        print(f"{letter}:{count}")
