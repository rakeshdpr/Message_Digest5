#include <bits/stdc++.h>
using namespace std;
class MD5 {
public:
    typedef unsigned int size_type; // must be 32bit
    MD5();
    MD5(const string& text);
    void update(const unsigned char* buf, size_type length); // unsigned char useful for working with raw binary data
    void update(const char* buf, size_type length); // char useful for string input, both have same name (function overloading)
   void finalize();
    string hexdigest() const; // i don't want the hexdigest function to change any of the state, so used const here
    friend ostream& operator<<(ostream&, MD5 md5); // making the output stream as friend to push the hex digest

private:
    void init();
    typedef unsigned char uint1; // 8bit
    typedef unsigned int uint4;  // 32bit
    enum { blocksize = 64 };

    void transform(const uint1 block[blocksize]);
     void decode(uint4 output[], const uint1 input[], size_type len);
     void encode(uint1 output[], const uint4 input[], size_type len);

    bool finalized;
    uint1 buffer[blocksize]; // bytes that didn't fit in last 64 byte chunk, 8x64=512 bits
    uint4 count[2];   // 64bit counter for number of bits (lo, hi)
    uint4 state[4];   // digest so far
    uint1 digest[16]; // the result , this is of 128 bit... since MD5 is an 128 bit encryprtion

    // low level logic operations
      uint4 F(uint4 x, uint4 y, uint4 z);
      uint4 G(uint4 x, uint4 y, uint4 z);
      uint4 H(uint4 x, uint4 y, uint4 z);
      uint4 I(uint4 x, uint4 y, uint4 z);
      uint4 rotate_left(uint4 x, int n);
      void FF(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
      void GG(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
      void HH(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
      void II(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac);
};

// string md5(const string str);

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

// here MD5::uint4 is the return type
// and MD5::F is the function

 MD5::uint4 MD5::F(uint4 x, uint4 y, uint4 z) {
    return x & y | ~x & z;
}

 MD5::uint4 MD5::G(uint4 x, uint4 y, uint4 z) {
    return x & z | y & ~z;
}

 MD5::uint4 MD5::H(uint4 x, uint4 y, uint4 z) {
    return x ^ y ^ z;
}

 MD5::uint4 MD5::I(uint4 x, uint4 y, uint4 z) {
    return y ^ (x | ~z);
}

 MD5::uint4 MD5::rotate_left(uint4 x, int n) {
    return (x << n) | (x >> (32 - n));
}

 void MD5::FF(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + F(b, c, d) + x + ac, s) + b;
}

 void MD5::GG(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + G(b, c, d) + x + ac, s) + b;
}

 void MD5::HH(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + H(b, c, d) + x + ac, s) + b;
}

 void MD5::II(uint4& a, uint4 b, uint4 c, uint4 d, uint4 x, uint4 s, uint4 ac) {
    a = rotate_left(a + I(b, c, d) + x + ac, s) + b;
}

MD5::MD5() {
    init();
}

MD5::MD5(const string& text) { 
    init();
    update(text.c_str(), text.length()); // here text.c_str is used for the first pointer, so that is can be passed as array
    finalize();
}

void MD5::init() {
    finalized = false;
    count[0] = 0;
    count[1] = 0;
    state[0] = 0x67452301;
    state[1] = 0xefcdab89;
    state[2] = 0x98badcfe;
    state[3] = 0x10325476;
}

void MD5::decode(uint4 output[], const uint1 input[], size_type len) {
    for (unsigned int i = 0, j = 0; j < len; i++, j += 4)
        output[i] = ((uint4)input[j]) | (((uint4)input[j + 1]) << 8) |
            (((uint4)input[j + 2]) << 16) | (((uint4)input[j + 3]) << 24);
}

void MD5::encode(uint1 output[], const uint4 input[], size_type len) {
    for (size_type i = 0, j = 0; j < len; i++, j += 4) {
        output[j] = input[i] & 0xff;
        output[j + 1] = (input[i] >> 8) & 0xff;
        output[j + 2] = (input[i] >> 16) & 0xff;
        output[j + 3] = (input[i] >> 24) & 0xff;
    }
}
// block[blocksize] takes a total size of 512 bits
// each , block[i] have a character
// and 64 such elements are there
// so 64 character are there, hence 8*64=512 bits
void MD5::transform(const uint1 block[blocksize]) {
    uint4 a = state[0], b = state[1], c = state[2], d = state[3], x[16];
    decode(x, block, blocksize);

    /* Round 1 */
    FF(a, b, c, d, x[0], S11, 0xd76aa478); /* 1 */
    FF(d, a, b, c, x[1], S12, 0xe8c7b756); /* 2 */
    FF(c, d, a, b, x[2], S13, 0x242070db); /* 3 */
    FF(b, c, d, a, x[3], S14, 0xc1bdceee); /* 4 */
    FF(a, b, c, d, x[4], S11, 0xf57c0faf); /* 5 */
    FF(d, a, b, c, x[5], S12, 0x4787c62a); /* 6 */
    FF(c, d, a, b, x[6], S13, 0xa8304613); /* 7 */
    FF(b, c, d, a, x[7], S14, 0xfd469501); /* 8 */
    FF(a, b, c, d, x[8], S11, 0x698098d8); /* 9 */
    FF(d, a, b, c, x[9], S12, 0x8b44f7af); /* 10 */
    FF(c, d, a, b, x[10], S13, 0xffff5bb1); /* 11 */
    FF(b, c, d, a, x[11], S14, 0x895cd7be); /* 12 */
    FF(a, b, c, d, x[12], S11, 0x6b901122); /* 13 */
    FF(d, a, b, c, x[13], S12, 0xfd987193); /* 14 */
    FF(c, d, a, b, x[14], S13, 0xa679438e); /* 15 */
    FF(b, c, d, a, x[15], S14, 0x49b40821); /* 16 */

    /* Round 2 */
    GG(a, b, c, d, x[1], S21, 0xf61e2562); /* 17 */
    GG(d, a, b, c, x[6], S22, 0xc040b340); /* 18 */
    GG(c, d, a, b, x[11], S23, 0x265e5a51); /* 19 */
    GG(b, c, d, a, x[0], S24, 0xe9b6c7aa); /* 20 */
    GG(a, b, c, d, x[5], S21, 0xd62f105d); /* 21 */
    GG(d, a, b, c, x[10], S22, 0x02441453); /* 22 */
    GG(c, d, a, b, x[15], S23, 0xd8a1e681); /* 23 */
    GG(b, c, d, a, x[4], S24, 0xe7d3fbc8); /* 24 */
    GG(a, b, c, d, x[9], S21, 0x21e1cde6); /* 25 */
    GG(d, a, b, c, x[14], S22, 0xc33707d6); /* 26 */
    GG(c, d, a, b, x[3], S23, 0xf4d50d87); /* 27 */
    GG(b, c, d, a, x[8], S24, 0x455a14ed); /* 28 */
    GG(a, b, c, d, x[13], S21, 0xa9e3e905); /* 29 */
    GG(d, a, b, c, x[2], S22, 0xfcefa3f8); /* 30 */
    GG(c, d, a, b, x[7], S23, 0x676f02d9); /* 31 */
    GG(b, c, d, a, x[12], S24, 0x8d2a4c8a); /* 32 */

    /* Round 3 */
    HH(a, b, c, d, x[5], S31, 0xfffa3942); /* 33 */
    HH(d, a, b, c, x[8], S32, 0x8771f681); /* 34 */
    HH(c, d, a, b, x[11], S33, 0x6d9d6122); /* 35 */
    HH(b, c, d, a, x[14], S34, 0xfde5380c); /* 36 */
    HH(a, b, c, d, x[1], S31, 0xa4beea44); /* 37 */
    HH(d, a, b, c, x[4], S32, 0x4bdecfa9); /* 38 */
    HH(c, d, a, b, x[7], S33, 0xf6bb4b60); /* 39 */
    HH(b, c, d, a, x[10], S34, 0xbebfbc70); /* 40 */
    HH(a, b, c, d, x[13], S31, 0x289b7ec6); /* 41 */
    HH(d, a, b, c, x[0], S32, 0xeaa127fa); /* 42 */
    HH(c, d, a, b, x[3], S33, 0xd4ef3085); /* 43 */
    HH(b, c, d, a, x[6], S34, 0x04881d05); /* 44 */
    HH(a, b, c, d, x[9], S31, 0xd9d4d039); /* 45 */
    HH(d, a, b, c, x[12], S32, 0xe6db99e5); /* 46 */
    HH(c, d, a, b, x[15], S33, 0x1fa27cf8); /* 47 */
    HH(b, c, d, a, x[2], S34, 0xc4ac5665); /* 48 */

    /* Round 4 */
    II(a, b, c, d, x[0], S41, 0xf4292244); /* 49 */
    II(d, a, b, c, x[7], S42, 0x432aff97); /* 50 */
    II(c, d, a, b, x[14], S43, 0xab9423a7); /* 51 */
    II(b, c, d, a, x[5], S44, 0xfc93a039); /* 52 */
    II(a, b, c, d, x[12], S41, 0x655b59c3); /* 53 */
    II(d, a, b, c, x[3], S42, 0x8f0ccc92); /* 54 */
    II(c, d, a, b, x[10], S43, 0xffeff47d); /* 55 */
    II(b, c, d, a, x[1], S44, 0x85845dd1); /* 56 */
    II(a, b, c, d, x[8], S41, 0x6fa87e4f); /* 57 */
    II(d, a, b, c, x[15], S42, 0xfe2ce6e0); /* 58 */
    II(c, d, a, b, x[6], S43, 0xa3014314); /* 59 */
    II(b, c, d, a, x[13], S44, 0x4e0811a1); /* 60 */
    II(a, b, c, d, x[4], S41, 0xf7537e82); /* 61 */
    II(d, a, b, c, x[11], S42, 0xbd3af235); /* 62 */
    II(c, d, a, b, x[2], S43, 0x2ad7d2bb); /* 63 */
    II(b, c, d, a, x[9], S44, 0xeb86d391); /* 64 */

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;

    memset(x, 0, sizeof x); // reseting x for another use
}

void MD5::update(const unsigned char* input, size_type length) {
    size_type index = (count[0] / 8) % blocksize; // number of byte modulo 64

    if ((count[0] += length << 3) < (length << 3))
        count[1]++;
    count[1] += length >> 29;

    size_type firstpart = 64 - index;
    size_type i;

    if (length >= firstpart) {
        // buffer is a array having 64 element
        // each element is of 8 bits
        memcpy(&buffer[index], input, firstpart);
        transform(buffer);

        for (i = firstpart; i + blocksize <= length; i += blocksize) // 64 x 8 = 512 shifting to the 512th bit each time

            transform(&input[i]); // passing the pointer

        index = 0;
    } else
        i = 0;

    memcpy(&buffer[index], &input[i], length - i);
}

void MD5::update(const char* input, size_type length) {
    update((const unsigned char*)input, length);
}

void MD5::finalize() {
     unsigned char padding[64] = {0x80};
    if (!finalized) {
        unsigned char bits[8];
        encode(bits, count, 8);

        size_type index = count[0] / 8 % 64;
        size_type padLen = (index < 56) ? (56 - index) : (120 - index);
        ////////////////////////////// taking care of the last and second last multiple of 512 in the MD5 algorithm
        update(padding, padLen);

        update(bits, 8);
        /////////////////////////////
        encode(digest, state, 16);

        memset(buffer, 0, sizeof buffer);
        memset(count, 0, sizeof count);

        finalized = true;
    }

}

string MD5::hexdigest() const {
    if (!finalized)
        return "";

    char buf[33];
    for (int i = 0; i < 16; i++)
        sprintf(buf + i * 2, "%02x", digest[i]);

    return string(buf);
}

ostream& operator<<(ostream& out, MD5 md5) { // the ampercent use for chaining purpose;
    return out << md5.hexdigest();
}

// we use the stream operator like cout<<"string"<<endl;
// here we have object, so we can't use cout<<OBJECT; thus using stream overloading

// note cout is a object from the class ostream
// cin is a object from the class istream


int main() {
    char menu;
    cout << "\n********** Message Digest 5 (MD5) Encoder & Decoder *********" << endl;
    cout << "\n(1)The Encoder will Encrypt your string to MD5" << endl;
    cout << "(2)The Decoder will Decode your MD5 hash to string, from your given set of potential strings" << endl;
    cout << "\n------------------------------------------------------------" << endl;
    cout << "Press [ E ] For MD5 Encoder " << endl;
    cout << "Press [ D ] For MD5 Decoder " << endl;
    cout << "---------------------------" << endl;
    cin >> menu; cout<<"------------------------------------------------------------"<<endl;
    cin.ignore(); // Ignore newline character after menu input

    if (menu == 'E') {
        cout << "\n___________________ STRING TO MD5 ENCODER __________________ \n" << endl;
        cout << "Please enter the location of txt file whose strings you want to encode: ";
        string inputFilePath;
        getline(cin, inputFilePath);

        ifstream inputFile(inputFilePath);
        if (!inputFile) {
            cerr << "Error opening input file!" << endl;
            return 1;
        }

        cout << "Please enter the location of the output file: ";
        string outputFilePath;
        getline(cin, outputFilePath);

        ofstream outputFile(outputFilePath);
        if (!outputFile) {
            cerr << "Error opening output file!" << endl;
            return 1;
        }

        string line;
        while (getline(inputFile, line)) {
            MD5 md5 = MD5(line);
            outputFile <<"\""<<line <<"\" ----------->"<< " " << md5.hexdigest() << endl;
        }

        inputFile.close();
        outputFile.close();
        cout << "\nYour encoded strings are given in the output file." << endl;

    } else if (menu == 'D') {
        cout << "\n_____________________ MD5 TO STRING ENCODER __________________ \n" << endl;
        cout << "Please enter the hash which you want to decode: ";
        string hash;
        cin>>hash; cin.ignore();

        cout << "Please enter the location of the txt file having a potential list of strings: ";
        string inputFilePath;
        getline(cin, inputFilePath);

        ifstream inputFile(inputFilePath);
        if (!inputFile) {
            cerr << "Error opening input file!" << endl;
            return 1;
        }

        bool found = false;
        string line;
        while (getline(inputFile, line)) {
            MD5 md5 = MD5(line);
            if (md5.hexdigest() == hash) {
                cout << "\nString " << "\""<<line<<"\""<< " corresponds to hash--> " << hash << endl;
                found = true;
                break;
            }
        }

        inputFile.close();

        if (!found) {
            cout << "\nOOPS!! No string found for the given hash." << endl;
        }

    } else {
        cout << "You entered an invalid key." << endl;
    }

    cout << "\nENTER ANY KEY TO EXIT: ";
    int exitwait; 
    cin >> exitwait;

    return 0;
}
