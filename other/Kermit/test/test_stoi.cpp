#include <iostream>
#include <string>
#include <stoi16.hpp>

main ()
{
cout << stoi16 (string ("0")) << endl;
cout << stoi16 (string ("1")) << endl;
cout << stoi16 (string ("2")) << endl;
cout << stoi16 (string ("f")) << endl;
cout << stoi16 (string ("00")) << endl;
cout << stoi16 (string ("ff")) << endl;
cout << stoi16 (string ("41")) << endl;
cout << stoi16 (string ("73")) << endl;
cout << stoi16 (string ("50")) << endl;

}
