#include "pch.hpp"

void PrintArgs()
{
    std::cout << "Argument format: <string> <type> <key>\n";
    std::cout << "Types: r == ROL, x == XOR\n";
    std::cout << "String should be surrounded by quotes for safety\n";
}

inline void RolDecrypt(std::string& str, int key)
{
    uint8_t last;

    for (char& ch : str)
    {
        last = static_cast<uint8_t>(ch);
        ch = (last << key) | (last >> (8 - key));
    }
}

inline void XorDecrypt(std::string& str, int key)
{
    char last;

    for (char& ch : str)
    {
        last = ch;
        ch = last ^ key;
    }
}

int main(int argc, char* argv[])
{
    // Checking args
    
    if (argc < 4)
    {
        PrintArgs();
        return 0;
    }

    const char mode = argv[2][0];

    if (mode != 'r' && mode != 'x')
    {
        std::cout << "ERROR: unrecognized decryption mode\n";
        PrintArgs();
        return 1;
    }

    if (!std::isdigit(argv[3][0]))
    {
        std::cout << "ERROR: invalid key provided\n";
        PrintArgs();
        return 2;
    }

    // Formatting input

    std::string str = argv[1];
    std::string FormattedStr;

    for (size_t i = 0, const sz = str.size(); i < sz; ++i)
    {
        char FirstCh = str[i];

        if (FirstCh == '\\' && i + 1 < sz)
        {
            ++i;

            FirstCh = str[i];
            char CurrCh = -1;

            switch (FirstCh)
            {
            case '\'': CurrCh = '\''; break;
            case '\"': CurrCh = '\"'; break;
            case '\?': CurrCh = '\?'; break;
            case '\\': CurrCh = '\\'; break;
            case 'a':  CurrCh = '\a'; break;
            case 'b':  CurrCh = '\b'; break;
            case 'f':  CurrCh = '\f'; break;
            case 'n':  CurrCh = '\n'; break;
            case 'r':  CurrCh = '\r'; break;
            case 't':  CurrCh = '\t'; break;
            case 'v':  CurrCh = '\v'; break;
            case '0':  CurrCh = '\0'; break;
            }

            if (CurrCh != -1)
            {
                FormattedStr += CurrCh;
            }
            else if (i + 2 < sz && str[i] == 'x')
            {
                FormattedStr += static_cast<char>(std::stoi(str.substr(i + 1, 2), nullptr, 16));
                i += 2;
            }
        }
        else FormattedStr += str[i];
    }

    const int key = std::stoi(argv[3]);

    if (mode == 'r')
    {
        RolDecrypt(FormattedStr, key);
    }
    else
    {
        XorDecrypt(FormattedStr, key);
    }

    std::cout << "RESULT: \"" << FormattedStr << "\"\n";
    return 0;
}