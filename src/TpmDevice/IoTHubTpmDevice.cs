using System;
using System.Text;

namespace TpmDevice
{
    /// <summary>
    /// A helper for working with Tpm (<see cref="TpmDevice"/>) for IoT Hub specific functionality.
    /// </summary>
    public class IoTHubTpmDevice : TpmDevice
    {
        private const string TargetFormatDevice = "{0}/devices/{1}";
        private const string TargetFormatModule = "{0}/devices/{1}/modules/{2}";
        private const string SharedAccessSignatureFormat = "SharedAccessSignature sr={0}&sig={1}&se={2}";
        private const string ConnectionStringFormatDevice = "HostName={0};DeviceId={1};SharedAccessSignature={2}";
        private const string ConnectionStringFormatModule = "HostName={0};DeviceId={1};ModuleId={3};SharedAccessSignature={2}";
        private const string UriRegexFormat = @"^([^\/]*)\/([^\/]*)(?:\/([^\/]*))?$";
        private const string UriFormatDevice = "{0}/{1}";
        private const string UriFormatModule = "{0}/{1}/{2}";

        private const uint DefaultTllSeconds = 3600;

        /// <summary>
        /// Creates an instance of <see cref="IoTHubTpmDevice"/>
        /// </summary>
        /// <param name="logicalDeviceId"></param>
        public IoTHubTpmDevice(uint logicalDeviceId) : base(logicalDeviceId) { }

        /// <summary>
        /// Gets whether the slot has been provisioned.
        /// This considers the persisted data and does not test connection to the hub
        /// </summary>
        /// <returns></returns>
        public bool IsProvisioned() => !string.IsNullOrWhiteSpace(GetPersistedUri());

        /// <summary>
        /// Gets the host name stored in the TPM Uri. The format is usually {iot-hub-name}.azure-devices.net
        /// </summary>
        /// <returns></returns>
        public string GetHostName() => ExtractFromTpmUri(GetPersistedUri()).hostName;

        /// <summary>
        /// Gets the device identifier (DeviceId) stored in the TPM Uri.
        /// </summary>
        /// <returns></returns>
        public string GetDeviceId() => ExtractFromTpmUri(GetPersistedUri()).deviceId;

        /// <summary>
        /// Gets the module identifier (ModuleId) stored in the TPM Uri. When the Uri is for a device, the ModuleId will be empty
        /// </summary>
        /// <returns></returns>
        public string GetModuleId() => ExtractFromTpmUri(GetPersistedUri()).moduleId;

        /// <summary>
        /// Gets a valid connection string using the URI stored in the TPM and its associated key.
        /// The key is stored inthe TPM and cannot be retrieved.
        /// </summary>
        /// <param name="ttlSeconds">the duration of lifetime for the connection string in seconds</param>
        /// <returns></returns>
        public string GetConnectionString(uint ttlSeconds = DefaultTllSeconds)
        {
            // get the raw Uri stored in the TPM slot
            var rawUri = GetPersistedUri();

            // extract data from the raw Uri and ensure we have the host name and device id
            var (hostName, deviceId, moduleId) = ExtractFromTpmUri(rawUri);
            if (string.IsNullOrWhiteSpace(hostName) || string.IsNullOrWhiteSpace(deviceId)) return string.Empty;

            // generate the Shared Access Signature (SaS)
            string sasToken = GenerateSaSToken(hostName, deviceId, moduleId, ttlSeconds);
            if (string.IsNullOrWhiteSpace(sasToken)) return string.Empty;

            // form the connection string
            var connectionString = string.Format(
                string.IsNullOrWhiteSpace(moduleId) ? ConnectionStringFormatDevice : ConnectionStringFormatModule,
                hostName,
                deviceId,
                sasToken,
                moduleId);
            return connectionString;
        }

        /// <summary>
        /// Provision the uri in the TPM
        /// </summary>
        /// <param name="hostName">the iot hub host name</param>
        /// <param name="deviceId">the device identity</param>
        /// <param name="moduleId">the module identity</param>
        public void Provision(string hostName, string deviceId, string moduleId = null)
        {
            var uri = string.Format(
                string.IsNullOrWhiteSpace(moduleId) ? UriFormatDevice : UriFormatModule,
                hostName,
                deviceId,
                moduleId);
            SetPersistedUri(uri);
        }

        /// <summary>
        /// Provision the uri and the key in the TPM
        /// </summary>
        /// <param name="hostName">the iot hub host name</param>
        /// <param name="deviceId">the device identity</param>
        /// <param name="key">the access key</param>
        public void Provision(string hostName, string deviceId, byte[] key)
        {
            Provision(hostName, deviceId);
            Provision(key);
        }

        /// <summary>
        /// Provision the uri and the key in the TPM
        /// </summary>
        /// <param name="hostName">the iot hub host name</param>
        /// <param name="deviceId">the device identity</param>
        /// <param name="moduleId">the module identity</param>
        /// <param name="key">the access key</param>
        public void Provision(string hostName, string deviceId, string moduleId, byte[] key)
        {
            Provision(hostName, deviceId, moduleId);
            Provision(key);
        }

        /// <summary>
        /// Provision the uri and the key in the TPM
        /// </summary>
        /// <param name="hostName">the iot hub host name</param>
        /// <param name="deviceId">the device identity</param>
        /// <param name="moduleId">the module identity</param>
        /// <param name="base64Key">the access key encoded in base 64</param>
        public void Provision(string hostName, string deviceId, string moduleId, string base64Key)
        {
            var key = Convert.FromBase64String(base64Key);
            Provision(hostName, deviceId, moduleId, key);
        }

        private string GenerateSaSToken(string hostName, string deviceId, string moduleId, uint ttlSeconds)
        {
            var expiry = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            expiry += ttlSeconds;

            // prepare the target to sign
            var audience = string.Format(string.IsNullOrWhiteSpace(moduleId) ? TargetFormatDevice : TargetFormatModule,
                                         hostName,
                                         deviceId,
                                         moduleId);

            // form the fields to sign convert to bytes
            var toSign = string.Join("\n", audience, expiry);
            var toSignBytes = Encoding.UTF8.GetBytes(toSign);

            // sign the target bytes with the TPM
            var signedBytes = Sign(toSignBytes);

            // ensure we have signed bytes
            if (signedBytes != null && signedBytes.Length < 0) return string.Empty;

            // encode the output
            var signature = Convert.ToBase64String(signedBytes);
            signature = AzureUrlEncode(signature);

            // return the assembled connection string
            return string.Format(SharedAccessSignatureFormat, audience, signature, expiry);
        }

        private static string AzureUrlEncode(string stringIn)
        {
            string[] conversionTable = {
            "\0", "%01", "%02", "%03", "%04", "%05", "%06", "%07", "%08", "%09", "%0a", "%0b", "%0c", "%0d", "%0e", "%0f",
            "%10", "%11", "%12", "%13", "%14", "%15", "%16", "%17", "%18", "%19", "%1a", "%1b", "%1c", "%1d", "%1e", "%1f",
            "%20", "!", "%22", "%23", "%24", "%25", "%26", "%27", "(", ")", "*", "%2b", "%2c", "-", ".", "%2f",
            "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "%3a", "%3b", "%3c", "%3d", "%3e", "%3f",
            "%40", "A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O",
            "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z", "%5b", "%5c", "%5d", "%5e", "_",
            "%60", "a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o",
            "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", "%7b", "%7c", "%7d", "%7e", "%7f",
            "%c2%80", "%c2%81", "%c2%82", "%c2%83", "%c2%84", "%c2%85", "%c2%86", "%c2%87", "%c2%88", "%c2%89", "%c2%8a", "%c2%8b", "%c2%8c", "%c2%8d", "%c2%8e", "%c2%8f",
            "%c2%90", "%c2%91", "%c2%92", "%c2%93", "%c2%94", "%c2%95", "%c2%96", "%c2%97", "%c2%98", "%c2%99", "%c2%9a", "%c2%9b", "%c2%9c", "%c2%9d", "%c2%9e", "%c2%9f",
            "%c2%a0", "%c2%a1", "%c2%a2", "%c2%a3", "%c2%a4", "%c2%a5", "%c2%a6", "%c2%a7", "%c2%a8", "%c2%a9", "%c2%aa", "%c2%ab", "%c2%ac", "%c2%ad", "%c2%ae", "%c2%af",
            "%c2%b0", "%c2%b1", "%c2%b2", "%c2%b3", "%c2%b4", "%c2%b5", "%c2%b6", "%c2%b7", "%c2%b8", "%c2%b9", "%c2%ba", "%c2%bb", "%c2%bc", "%c2%bd", "%c2%be", "%c2%bf",
            "%c3%80", "%c3%81", "%c3%82", "%c3%83", "%c3%84", "%c3%85", "%c3%86", "%c3%87", "%c3%88", "%c3%89", "%c3%8a", "%c3%8b", "%c3%8c", "%c3%8d", "%c3%8e", "%c3%8f",
            "%c3%90", "%c3%91", "%c3%92", "%c3%93", "%c3%94", "%c3%95", "%c3%96", "%c3%97", "%c3%98", "%c3%99", "%c3%9a", "%c3%9b", "%c3%9c", "%c3%9d", "%c3%9e", "%c3%9f",
            "%c3%a0", "%c3%a1", "%c3%a2", "%c3%a3", "%c3%a4", "%c3%a5", "%c3%a6", "%c3%a7", "%c3%a8", "%c3%a9", "%c3%aa", "%c3%ab", "%c3%ac", "%c3%ad", "%c3%ae", "%c3%af",
            "%c3%b0", "%c3%b1", "%c3%b2", "%c3%b3", "%c3%b4", "%c3%b5", "%c3%b6", "%c3%b7", "%c3%b8", "%c3%b9", "%c3%ba", "%c3%bb", "%c3%bc", "%c3%bd", "%c3%be", "%c3%bf" };
            string stringOut = "";
            foreach (char n in stringIn)
            {
                stringOut += conversionTable[n];
            }
            return stringOut;
        }

        /// <summary>
        /// Get the parts from raw TPM data
        /// </summary>
        /// <param name="rawUri">the data stored in the format '{host-name}/{device-id}[/{module-id}]</param>
        /// <returns></returns>
        private static (string hostName, string deviceId, string moduleId) ExtractFromTpmUri(string rawUri)
        {
            string hostName = null, deviceId = null, moduleId = null;

            var regEx = new System.Text.RegularExpressions.Regex(UriRegexFormat);
            var match = regEx.Match(rawUri);
            if (match.Success)
            {
                hostName = match.Groups[1].Value;
                deviceId = match.Groups[2].Value;
                moduleId = match.Groups[3].Value;
            }

            return (hostName, deviceId, moduleId);
        }
    }
}
