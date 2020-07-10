using System;
using System.Linq;
using System.Text;
using Tpm2Lib;

namespace TpmDevice
{
    /// <summary>
    /// A wrapper class for accessing TPM functionality.
    /// This wraps around the Microsoft Library Microsoft.TSS
    /// available at https://github.com/microsoft/TSS.MSR
    /// </summary>
    public class TpmDevice
    {
        private const uint AIOTH_PERSISTED_URI_INDEX = ((uint)Ht.NvIndex << 24) | 0x0040_0100;
        private const uint AIOTH_PERSISTED_KEY_HANDLE = ((uint)Ht.Persistent << 24) | 0x0000_0100;
        private const uint TPM_20_SRK_HANDLE = ((uint)Ht.Persistent << 24) | 0x0000_0001;
        private const uint TPM_20_EK_HANDLE = ((uint)Ht.Persistent << 24) | 0x0001_0001;

        private const string TargetFormatDevice = "{0}/devices/{1}";
        private const string TargetFormatModule = "{0}/devices/{1}/modules/{2}";
        private const string ConnectionStringFormatDevice = "HostName={0};DeviceId={1};SharedAccessSignature={2}";
        private const string ConnectionStringFormatModule = "HostName={0};DeviceId={1};ModuleId={3};SharedAccessSignature={2}";
        private const string SharedAccessSignatureFormat = "SharedAccessSignature sr={0}&sig={1}&se={2}";
        private const string UriRegexFormat = @"^([^\/]*)\/([^\/]*)(?:\/([^\/]*))?$";
        private const string UriFormatDevice = "{0}/{1}";
        private const string UriFormatModule = "{0}/{1}/{2}";

        private const uint DefaultTllSeconds = 3600;

        private readonly uint logicalDeviceId = 0;

        /// <summary>
        /// Creates an instance of <see cref="TpmDevice"/>
        /// </summary>
        /// <param name="logicalDeviceId"></param>
        public TpmDevice(uint logicalDeviceId)
        {
            this.logicalDeviceId = logicalDeviceId;
        }

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

        #region TPM Methods

        private string GetPersistedUri()
        {
            TpmHandle nvUriHandle = new TpmHandle(AIOTH_PERSISTED_URI_INDEX + logicalDeviceId);

            try
            {
                string iotHubUri;

                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                using (var tpm = new Tpm2(tpmDevice))
                {
                    // Read the URI from the TPM
                    NvPublic nvPublic = tpm.NvReadPublic(nvUriHandle, out byte[] name);
                    var nvData = tpm.NvRead(nvUriHandle, nvUriHandle, nvPublic.dataSize, 0);

                    // Convert the data to a srting for output
                    iotHubUri = Encoding.UTF8.GetString(nvData);
                }

                return iotHubUri;
            }
            catch { }

            return string.Empty;
        }

        /// <summary>
        /// Gets the identifier of the device
        /// </summary>
        /// <returns></returns>
        public string GetHardwareDeviceId()
        {
            TpmHandle srkHandle = new TpmHandle(TPM_20_SRK_HANDLE);

            try
            {
                string hardwareDeviceId;

                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                using (var tpm = new Tpm2(tpmDevice))
                {
                    // Read the URI from the TPM
                    TpmPublic srk = tpm.ReadPublic(srkHandle, out byte[] name, out byte[] qualifiedName);

                    // Calculate the hardware device id for this logical device
                    byte[] deviceId = CryptoLib.HashData(TpmAlgId.Sha256, BitConverter.GetBytes(logicalDeviceId), name);

                    // Produce the output string
                    hardwareDeviceId = string.Join(string.Empty, deviceId.Select(b => b.ToString("x2")));
                }

                return hardwareDeviceId;
            }
            catch { }

            return string.Empty;
        }

        /// <summary>
        /// Get the endorsement key from the TPM. If the key has not yet been set, a new one is generated
        /// </summary>
        /// <returns></returns>
        public static byte[] GetEndorsementKey()
        {
            // picked from https://github.com/Azure/azure-iot-sdk-csharp/blob/e1dd08eacd1caf58f3b318d8ad5ad94dde961d78/security/tpm/src/SecurityProviderTpmHsm.cs#L258-L324
            TpmHandle ekHandle = new TpmHandle(TPM_20_EK_HANDLE);
            byte[] result = Array.Empty<byte>();

            try
            {
                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                using (var tpm = new Tpm2(tpmDevice))
                {
                    // Read EK from the TPM, temporarily allowing errors
                    TpmPublic ekPub = tpm.
                        _AllowErrors()
                        .ReadPublic(ekHandle, out byte[] name, out byte[] qualifiedName);

                    // if the last command did not succeed, we do not have an endorsement key yet, so create it
                    if (!tpm._LastCommandSucceeded())
                    {
                        // Get the real EK ready.
                        TpmPublic ekTemplate = new TpmPublic(
                            TpmAlgId.Sha256,
                            ObjectAttr.FixedTPM | ObjectAttr.FixedParent | ObjectAttr.SensitiveDataOrigin |
                            ObjectAttr.AdminWithPolicy | ObjectAttr.Restricted | ObjectAttr.Decrypt,
                            new byte[] {
                            0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
                            0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa
                            },
                            new RsaParms(
                                new SymDefObject(TpmAlgId.Aes, 128, TpmAlgId.Cfb),
                                new NullAsymScheme(),
                                2048,
                                0),
                            new Tpm2bPublicKeyRsa(new byte[2048 / 8]));

                        TpmHandle keyHandle = tpm.CreatePrimary(
                            new TpmHandle(TpmHandle.RhEndorsement),
                            new SensitiveCreate(),
                            ekTemplate,
                            Array.Empty<byte>(),
                            Array.Empty<PcrSelection>(),
                            out ekPub,
                            out CreationData creationData,
                            out byte[] creationHash,
                            out TkCreation creationTicket);

                        tpm.EvictControl(TpmHandle.RhOwner, keyHandle, ekHandle);
                        tpm.FlushContext(keyHandle);
                    }

                    // Get the EK representation
                    result = ekPub.GetTpm2BRepresentation();
                }
            }
            catch { }


            return result;
        }

        /// <summary>
        /// Sign data using the key stored in the TPM. The signing is done inside the TPM to avoid exposing the key.
        /// This is similar to using <see cref="System.Security.Cryptography.SHA256CryptoServiceProvider"/> which
        /// uses <see cref="System.Security.Cryptography.HMACSHA256"/> inside.
        /// </summary>
        /// <param name="data"></param>
        /// <returns></returns>
        public byte[] Sign(byte[] data)
        {
            TpmHandle hmacKeyHandle = new TpmHandle(AIOTH_PERSISTED_KEY_HANDLE + logicalDeviceId);
            int dataIndex = 0;
            byte[] iterationBuffer, result = Array.Empty<byte>();

            try
            {
                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                using (var tpm = new Tpm2(tpmDevice))
                {
                    if (data.Length <= 1024)
                    {
                        // Calculate the HMAC in one shot
                        result = tpm.Hmac(hmacKeyHandle, data, TpmAlgId.Sha256);
                    }
                    else
                    {
                        // Start the HMAC sequence
                        TpmHandle hmacHandle = tpm.HmacStart(hmacKeyHandle, Array.Empty<byte>(), TpmAlgId.Sha256);
                        while (data.Length > dataIndex + 1024)
                        {
                            // Repeat to update the hmac until we only hace <=1024 bytes left
                            iterationBuffer = new byte[1024];
                            Array.Copy(data, dataIndex, iterationBuffer, 0, 1024);
                            tpm.SequenceUpdate(hmacHandle, iterationBuffer);
                            dataIndex += 1024;
                        }

                        // Finalize the hmac with the remainder of the data
                        iterationBuffer = new byte[data.Length - dataIndex];
                        Array.Copy(data, dataIndex, iterationBuffer, 0, data.Length - dataIndex);
                        result = tpm.SequenceComplete(hmacHandle, iterationBuffer, TpmHandle.RhNull, out TkHashcheck nullChk);
                    }
                }
            }
            catch { }

            return result;
        }

        private void SetPersistedUri(string uri)
        {
            TpmHandle nvHandle = new TpmHandle(AIOTH_PERSISTED_URI_INDEX + logicalDeviceId);
            TpmHandle ownerHandle = new TpmHandle(TpmRh.Owner);
            UTF8Encoding utf8 = new UTF8Encoding();
            byte[] nvData = utf8.GetBytes(uri);

            // Open the TPM
            Tpm2Device tpmDevice = new TbsDevice();
            tpmDevice.Connect();
            using (var tpm = new Tpm2(tpmDevice))
            {
                // Define the store
                tpm.NvDefineSpace(ownerHandle,
                                  Array.Empty<byte>(),
                                  new NvPublic(nvHandle,
                                               TpmAlgId.Sha256,
                                               NvAttr.Authwrite | NvAttr.Authread | NvAttr.NoDa,
                                               Array.Empty<byte>(),
                                               (ushort)nvData.Length));

                // Write the store
                tpm.NvWrite(nvHandle, nvHandle, nvData, 0);
            }
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
        /// Provision the key in the TPM
        /// </summary>
        /// <param name="key">the access key</param>
        public void Provision(byte[] key)
        {
            TpmHandle ownerHandle = new TpmHandle(TpmRh.Owner);
            TpmHandle hmacKeyHandle = new TpmHandle(AIOTH_PERSISTED_KEY_HANDLE + logicalDeviceId);
            TpmHandle srkHandle = new TpmHandle(TPM_20_SRK_HANDLE);

            // Open the TPM
            Tpm2Device tpmDevice = new TbsDevice();
            tpmDevice.Connect();
            using (var tpm = new Tpm2(tpmDevice))
            {
#pragma warning disable IDE0059 // Value assigned to symbol is never used
                // Import the HMAC key under the SRK
                TpmPrivate hmacPrv = tpm.Create(srkHandle,
                                                new SensitiveCreate(Array.Empty<byte>(),
                                                                    key),
                                                new TpmPublic(TpmAlgId.Sha256,
                                                              ObjectAttr.UserWithAuth | ObjectAttr.NoDA | ObjectAttr.Sign,
                                                              Array.Empty<byte>(),
                                                              new KeyedhashParms(new SchemeHmac(TpmAlgId.Sha256)),
                                                              new Tpm2bDigestKeyedhash()),
                                                Array.Empty<byte>(),
                                                Array.Empty<PcrSelection>(),
                                                out TpmPublic hmacPub,
                                                out CreationData creationData,
                                                out byte[] creationhash,
                                                out TkCreation ticket);
#pragma warning restore IDE0059 // Value assigned to symbol is never used

                // Load the HMAC key into the TPM
                TpmHandle loadedHmacKey = tpm.Load(srkHandle, hmacPrv, hmacPub);

                // Persist the key in NV
                tpm.EvictControl(ownerHandle, loadedHmacKey, hmacKeyHandle);

                // Unload the transient copy from the TPM
                tpm.FlushContext(loadedHmacKey);
            }
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

        /// <summary>
        /// Destroy the contents of the TPM in the slot
        /// </summary>
        public void Destroy()
        {
            TpmHandle nvHandle = new TpmHandle(AIOTH_PERSISTED_URI_INDEX + logicalDeviceId);
            TpmHandle ownerHandle = new TpmHandle(TpmRh.Owner);
            TpmHandle hmacKeyHandle = new TpmHandle(AIOTH_PERSISTED_KEY_HANDLE + logicalDeviceId);

            try
            {
                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                using (var tpm = new Tpm2(tpmDevice))
                {
                    // Destyroy the URI
                    tpm.NvUndefineSpace(ownerHandle, nvHandle);

                    // Destroy the HMAC key
                    tpm.EvictControl(ownerHandle, hmacKeyHandle, hmacKeyHandle);
                }
            }
            catch { }
        }

        #endregion

        #region Helpers

        private string GenerateSaSToken(string hostName, string deviceId, string moduleId, uint ttlSeconds)
        {
            var expiry = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            expiry += ttlSeconds;

            // prepare the target to sign
            var audience = string.Format(
                string.IsNullOrWhiteSpace(moduleId) ? TargetFormatDevice : TargetFormatModule,
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

        #endregion
    }
}
