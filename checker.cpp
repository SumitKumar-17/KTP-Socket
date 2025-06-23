#include <iostream>
#include <fstream>
#include <string>
using namespace std;

int main() {
    ifstream input("input.txt");
    ifstream output("output.txt");

    if (!input.is_open() || !output.is_open()) {
        cerr << "Error opening files!" << endl;
        return 1;
    }

    string input_line, output_line;
    int line_number = 0;
    bool mismatch_found = false;

    while (getline(input, input_line) && getline(output, output_line)) {
        line_number++;

        if (input_line != output_line) {
            mismatch_found = true;
            cout << "Mismatch found at line " << line_number << endl;
            cout << "Input:  " << input_line << endl;
            cout << "Output: " << output_line << endl;
            string::size_type pos = input_line.find_first_not_of(output_line);
            if (pos != string::npos) {
                cout << "100 characters after mismatch:" << endl;
                cout << input_line.substr(pos, 100) << endl;
            }
            break;
        }
    }

    if (!mismatch_found) {
        cout << "input.txt and output.txt are identical" << endl;
    }

    input.close();
    output.close();

    return 0;
}
