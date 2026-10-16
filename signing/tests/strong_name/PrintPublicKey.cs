using System;
using System.Reflection;

var name = Assembly.GetExecutingAssembly().GetName();
Console.WriteLine(Convert.ToHexString(name.GetPublicKeyToken()));
Console.WriteLine(Convert.ToHexString(name.GetPublicKey()));
