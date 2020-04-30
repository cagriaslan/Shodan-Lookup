import csv


def take_second(elem):
    return elem[1]


def shodan_parse(input_file):
    with open(input_file, 'r') as csvfile:
        first_line = csvfile.readline()
        column_number = first_line.count(',') + 1
        reader = csv.reader(csvfile)

        for idx in range(column_number):
            words = []
            csvfile.seek(0)
            for row in reader:
                csv_words = row[idx].split(" ")
                for i in csv_words:
                    words.append(i)

            words_counted = []
            for i in words:
                x = words.count(i)
                words_counted.append((i, x))
            countSet = set(words_counted)

            print(words_counted)
            with open(str(idx) + ".csv", 'w', newline='') as f:  # blank rows problem fixed
                writer = csv.writer(f)
                writer.writerows(sorted(countSet, key=take_second,
                                        reverse=True))  # Sorted by descending order of 2nd element which is
                # occurence count and write to csv


shodan_parse("file")  # Output of the shodan_bulk_search script
