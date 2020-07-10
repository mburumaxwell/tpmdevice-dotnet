using Microsoft.Azure.Devices.Client;
using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;
using Windows.ApplicationModel.Background;
using Windows.Foundation;

// The Background Application template is documented at http://go.microsoft.com/fwlink/?LinkID=533884&clcid=0x409

namespace ExampleUwpBackgroundApp
{
    public sealed class StartupTask : IBackgroundTask
    {
        private readonly EventWaitHandle iotHubOfflineEvent = new EventWaitHandle(true, EventResetMode.AutoReset);
        private BackgroundTaskDeferral deferral;
        private DeviceClient deviceClient;
        private readonly CancellationTokenSource backgroundCts = new CancellationTokenSource();

        public void Run(IBackgroundTaskInstance taskInstance)
        {
            // inform system that the background task may continue doing some work even after run has completed its execution
            deferral = taskInstance.GetDeferral();

            // listen for cancellation of the background task
            taskInstance.Canceled += OnBackgroundTaskCanceled;

            // start IoT hub connection
            EnsureConnected();
        }

        private void OnBackgroundTaskCanceled(IBackgroundTaskInstance sender, BackgroundTaskCancellationReason reason)
        {
            Debug.WriteLine("Background task {0} was cancelled. Reason: {1}", sender?.InstanceId, reason);

            // cancel the cancellation token source so that all operations linked/referenced are terminated
            backgroundCts.Cancel();
        }

        private void EnsureConnected()
        {
            IAsyncAction asyncAction = Windows.System.Threading.ThreadPool.RunAsync(async (workItem) =>
            {
                var ct = new CancellationTokenSource(); // TODO: move this CancellationTokenSource to a higher level
                var cancellationToken = ct.Token;

                while (true)
                {
                    cancellationToken.ThrowIfCancellationRequested();

                    iotHubOfflineEvent.WaitOne();

                    cancellationToken.ThrowIfCancellationRequested();

                    try
                    {
                        await ResetConnectionAsync(cancellationToken);
                    }
                    catch (Exception e)
                    {
                        iotHubOfflineEvent.Set();

                        Debug.WriteLine("{0} exception: {1}\n{2}", nameof(EnsureConnected), e.Message, e.StackTrace);
                    }

                    await Task.Delay(TimeSpan.FromMinutes(1), cancellationToken);
                }
            });
        }

        private async Task<string> GetConnectionStringAsync(CancellationToken cancellationToken)
        {
            var tpmDevice = new TpmDevice.TpmDevice(0);
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
                Debug.WriteLine("Waiting for connection string ...");
                await Task.Delay(TimeSpan.FromSeconds(1), cancellationToken);
            } while (true);

            return connectionString;
        }

        private async Task ResetConnectionAsync(CancellationToken cancellationToken)
        {
            Debug.WriteLine("{0} start", nameof(ResetConnectionAsync));
            // Attempt to close any existing connections before creating a new one
            if (deviceClient != null)
            {
                await deviceClient.CloseAsync(cancellationToken).ContinueWith((t) =>
                {
                    var e = t.Exception;
                    if (e != null)
                    {
                        Debug.WriteLine("existingClient.CloseAsync exception: {0}\n{1}", e.Message, e.StackTrace);
                    }
                });
            }

            // Get new SAS Token
            var deviceConnectionString = await GetConnectionStringAsync(cancellationToken);

            // Create DeviceClient. Application uses DeviceClient for telemetry messages, device twin as well as device management
            deviceClient = DeviceClient.CreateFromConnectionString(deviceConnectionString, TransportType.Mqtt);

            // For testing connection failure, we can use a short time-out.
#if DEBUG
            deviceClient.OperationTimeoutInMilliseconds = 30000;
#endif

            // set handler for connection status changed
            deviceClient.SetConnectionStatusChangesHandler((ConnectionStatus status, ConnectionStatusChangeReason reason) =>
            {
                string msg = "Connection changed: " + status.ToString() + " " + reason.ToString();
                Debug.WriteLine($"Connection changed: {status} {reason}");

                switch (reason)
                {
                    case ConnectionStatusChangeReason.Connection_Ok:
                        // No need to do anything, this is the expectation
                        break;

                    case ConnectionStatusChangeReason.Expired_SAS_Token:
                    case ConnectionStatusChangeReason.Bad_Credential:
                    case ConnectionStatusChangeReason.Retry_Expired:
                    case ConnectionStatusChangeReason.No_Network:
                        iotHubOfflineEvent.Set();
                        break;

                    case ConnectionStatusChangeReason.Client_Close:
                        // ignore this ... part of client shutting down.
                        break;

                    case ConnectionStatusChangeReason.Communication_Error:
                    case ConnectionStatusChangeReason.Device_Disabled:
                        // These are not implemented in the Azure SDK
                        break;

                    default:
                        break;
                }
            });

            Debug.WriteLine($"{nameof(ResetConnectionAsync)} end");
        }
    }
}
