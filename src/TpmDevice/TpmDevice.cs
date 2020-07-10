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
        private const uint PERSISTED_URI_INDEX = ((uint)Ht.NvIndex << 24) | 0x0040_0100;
        private const uint PERSISTED_KEY_HANDLE = ((uint)Ht.Persistent << 24) | 0x0000_0100;
        private const uint TPM_20_SRK_HANDLE = ((uint)Ht.Persistent << 24) | 0x0000_0001;
        private const uint TPM_20_EK_HANDLE = ((uint)Ht.Persistent << 24) | 0x0001_0001;

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
        /// <remarks>
        /// Picked from https://github.com/Azure/azure-iot-sdk-csharp/blob/e1dd08eacd1caf58f3b318d8ad5ad94dde961d78/security/tpm/src/SecurityProviderTpmHsm.cs#L258-L324
        /// </remarks>
        public static byte[] GetEndorsementKey()
        {
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
            TpmHandle hmacKeyHandle = new TpmHandle(PERSISTED_KEY_HANDLE + logicalDeviceId);
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

        /// <summary>
        /// Provision the key in the TPM
        /// </summary>
        /// <param name="key">the access key</param>
        public void Provision(byte[] key)
        {
            TpmHandle ownerHandle = new TpmHandle(TpmRh.Owner);
            TpmHandle hmacKeyHandle = new TpmHandle(PERSISTED_KEY_HANDLE + logicalDeviceId);
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
        /// Destroy the contents of the TPM in the slot
        /// </summary>
        public void Destroy()
        {
            TpmHandle nvHandle = new TpmHandle(PERSISTED_URI_INDEX + logicalDeviceId);
            TpmHandle ownerHandle = new TpmHandle(TpmRh.Owner);
            TpmHandle hmacKeyHandle = new TpmHandle(PERSISTED_KEY_HANDLE + logicalDeviceId);

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

        internal string GetPersistedUri()
        {
            TpmHandle nvUriHandle = new TpmHandle(PERSISTED_URI_INDEX + logicalDeviceId);

            try
            {
                string uri;

                // Open the TPM
                Tpm2Device tpmDevice = new TbsDevice();
                tpmDevice.Connect();
                using (var tpm = new Tpm2(tpmDevice))
                {
                    // Read the URI from the TPM
                    NvPublic nvPublic = tpm.NvReadPublic(nvUriHandle, out byte[] name);
                    var nvData = tpm.NvRead(nvUriHandle, nvUriHandle, nvPublic.dataSize, 0);

                    // Convert the data to a srting for output
                    uri = Encoding.UTF8.GetString(nvData);
                }

                return uri;
            }
            catch { }

            return string.Empty;
        }

        internal void SetPersistedUri(string uri)
        {
            TpmHandle nvHandle = new TpmHandle(PERSISTED_URI_INDEX + logicalDeviceId);
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
    }
}
