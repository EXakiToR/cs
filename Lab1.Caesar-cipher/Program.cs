using System;
using System.Text;

namespace Lab1.Caesar_cipher;

internal class Program
{
    static void Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        Console.InputEncoding = Encoding.UTF8;
        ConsoleUI.RunLoop();
    }
}
