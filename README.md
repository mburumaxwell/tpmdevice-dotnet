# TpmDevice

## Introduction

This library eases using a TPM in dotnet. It is built with the influence from the official one on Github (https://github.com/ms-iot/security/tree/master/Limpet) and on NuGet (https://www.nuget.org/packages/Microsoft.Devices.Tpm/) which has not been updated for while.
It is particularly useful when working with a BackgroundTask in Windows IoT built on UWP.

### Usage

Getting a connection string

```csharp
var tpmDevice = new TpmDevice(logicalDeviceId: 0);

var hostName = tpmDevice.GetHostName();
Console.WriteLine($"HostName: {hostName}");
Debug.WriteLine($"HostName: {hostName}");

var deviceId = tpmDevice.GetDeviceId();
Console.WriteLine($"DeviceId: {deviceId}");
Debug.WriteLine($"DeviceId: {deviceId}");

var connectionString = tpmDevice.GetConnectionString();
Console.WriteLine($"Connection String: {connectionString}");
Debug.WriteLine($"Connection String: {connectionString}");
```

Writing to the TPM (*Requires the device be provisioning in the IoT Hub*)

```csharp
var hostName = "contose.azure-devices.net";
var deviceId = "your-device-id-here";
var moduleId = null; // if no ModuleId is required, leave null, otherwise specify
var keyBase64 = "your-device-key-here";
var key = Convert.FromBase64String(keyBase64);
var tpmDevice = new TpmDevice(logicalDeviceId: 0);
tpmDevice.Provision(hostName, deviceId, moduleId);
tpmDevice.Provision(key);
System.Threading.Thread.Sleep(TimeSpan.FromSeconds(5)); // your device might need some time
var connectionString = tpmDevice.GetConnectionString();
Console.WriteLine(connectionString);
Debug.WriteLine(connectionString);
```

Sample usage in a background task for UWP IoT

```csharp
var tpmDevice = new TpmDevice(logicalDeviceId: 0);
string connectionString;

do
{
    // do not do anything if cancellation has been requested
    cancellationToken.ThrowIfCancellationRequested();

    try
    {
        connectionString = tpmDevice.GetConnectionString();
        if (!string.IsNullOrWhiteSpace(connectionString))
        {
            break; // connection string gotten break the loop
        }
    }
    catch (Exception)
    {
        // We'll just keep trying.
    }
    Logger.Verbose("Waiting for connection string ...");
    await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
} while (true);

Console.WriteLine(connectionString);
Debug.WriteLine(connectionString);
```

See [examples](./examples/) for more.

### Issues &amp; Comments

Please leave all comments, bugs, requests, and issues on the Issues page. We'll respond to your request ASAP!

### License

The Library is licensed under the [MIT](http://www.opensource.org/licenses/mit-license.php "Read more about the MIT license form") license. Refere to the [LICENSE](./LICENSE.md) file for more information.
