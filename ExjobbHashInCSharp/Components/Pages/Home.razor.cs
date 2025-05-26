using ExjobbHashInCSharp.Models;
using System.Security.Cryptography;
using System.Text;

namespace ExjobbHashInCSharp.Components.Pages;

public partial class Home
{
	private int _iterations = 1000;
	private int _pbkdf2Iterations = 10000;
	private bool _isRunning = false;
	private int _currentProgress = 0;

	private bool UseSHA256 { get; set; } = false;
	private bool UseSHA512 { get; set; } = false;
	private bool UseMD5 { get; set; } = false;
	private bool UseHMACSHA256 { get; set; } = false;
	private bool UseHMACSHA512 { get; set; } = false;
	private bool UsePBKDF2 { get; set; } = false;

	private List<HashTestResult> _testResults = [];

	private readonly int[] _inputSizes = { 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000 };
	private readonly int[] _passwordSizes = { 8, 16, 32, 64 };

	private readonly byte[] _hmacKey = new byte[32];

	protected override void OnInitialized()
	{
		using (var rng = RandomNumberGenerator.Create())
		{
			rng.GetBytes(_hmacKey);
		}

		base.OnInitialized();
	}

	private async Task RunHashTests()
	{
		if (_isRunning) return;

		_isRunning = true;
		_currentProgress = 0;
		_testResults.Clear();

		try
		{
			int totalTests = 0;
			if (UseSHA256 || UseSHA512 || UseMD5)
				totalTests += _inputSizes.Length * ((UseSHA256 ? 1 : 0) + (UseSHA512 ? 1 : 0) + (UseMD5 ? 1 : 0));
			if (UseHMACSHA256 || UseHMACSHA512)
				totalTests += _inputSizes.Length * ((UseHMACSHA256 ? 1 : 0) + (UseHMACSHA512 ? 1 : 0));
			if (UsePBKDF2)
				totalTests += _passwordSizes.Length;

			int testsCompleted = 0;

			if (totalTests == 0)
			{
				UseSHA256 = true;
				totalTests = _inputSizes.Length;
			}

			if (UseSHA256)
			{
				foreach (int size in _inputSizes)
				{
					var result = await RunHashTestAsync("SHA256", size, _iterations);
					_testResults.Add(result);
					testsCompleted++;
					_currentProgress = (testsCompleted * 100) / totalTests;
					StateHasChanged();
				}
			}

			if (UseSHA512)
			{
				foreach (int size in _inputSizes)
				{
					var result = await RunHashTestAsync("SHA512", size, _iterations);
					_testResults.Add(result);
					testsCompleted++;
					_currentProgress = (testsCompleted * 100) / totalTests;
					StateHasChanged();
				}
			}

			if (UseMD5)
			{
				foreach (int size in _inputSizes)
				{
					var result = await RunHashTestAsync("MD5", size, _iterations);
					_testResults.Add(result);
					testsCompleted++;
					_currentProgress = (testsCompleted * 100) / totalTests;
					StateHasChanged();
				}
			}

			if (UseHMACSHA256)
			{
				foreach (int size in _inputSizes)
				{
					var result = await RunHMACTestAsync("HMAC-SHA256", size, _iterations);
					_testResults.Add(result);
					testsCompleted++;
					_currentProgress = (testsCompleted * 100) / totalTests;
					StateHasChanged();
				}
			}

			if (UseHMACSHA512)
			{
				foreach (int size in _inputSizes)
				{
					var result = await RunHMACTestAsync("HMAC-SHA512", size, _iterations);
					_testResults.Add(result);
					testsCompleted++;
					_currentProgress = (testsCompleted * 100) / totalTests;
					StateHasChanged();
				}
			}

			if (UsePBKDF2)
			{
				foreach (int size in _passwordSizes)
				{
					var result = await RunPBKDF2TestAsync(size, _iterations);
					_testResults.Add(result);
					testsCompleted++;
					_currentProgress = (testsCompleted * 100) / totalTests;
					StateHasChanged();
				}
			}
		}
		finally
		{
			_isRunning = false;
			_currentProgress = 100;
		}
	}

	private Task<HashTestResult> RunHashTestAsync(string algorithm, int inputSize, int iterations)
	{
		return Task.Run(() => {
			byte[] randomBytes = new byte[inputSize];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(randomBytes);
			}
			string testString = Convert.ToBase64String(randomBytes).Substring(0, inputSize);

			using HashAlgorithm hashAlgorithm = algorithm switch
			{
				"SHA256" => SHA256.Create(),
				"SHA512" => SHA512.Create(),
				"MD5" => MD5.Create(),
				_ => SHA256.Create()
			};

			var stopwatch = new System.Diagnostics.Stopwatch();
			byte[] data = Encoding.UTF8.GetBytes(testString);

			WarmUpAndGarbageCollecting(hashAlgorithm, data, 10);

			stopwatch.Start();
			for (int i = 0; i < iterations; i++)
			{
				hashAlgorithm.ComputeHash(data);
			}
			stopwatch.Stop();

			double totalTimeMs = stopwatch.Elapsed.TotalMilliseconds;
			double timePerHashMicroseconds = (totalTimeMs * 1000) / iterations;
			double bytesPerSecond = (inputSize * iterations) / stopwatch.Elapsed.TotalSeconds;
			double mbPerSecond = bytesPerSecond / (1024 * 1024);

			return new HashTestResult
			{
				Algorithm = algorithm,
				InputSize = inputSize,
				Iterations = iterations,
				TotalTimeMs = totalTimeMs,
				TimePerHashMicroseconds = timePerHashMicroseconds,
				ThroughputMBps = mbPerSecond
			};
		});
	}

	private Task<HashTestResult> RunHMACTestAsync(string algorithm, int inputSize, int iterations)
	{
		return Task.Run(() => {
			byte[] randomBytes = new byte[inputSize];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(randomBytes);
			}
			string testString = Convert.ToBase64String(randomBytes).Substring(0, inputSize);
			byte[] data = Encoding.UTF8.GetBytes(testString);

			using HMAC hmac = algorithm switch
			{
				"HMAC-SHA256" => new HMACSHA256(_hmacKey),
				"HMAC-SHA512" => new HMACSHA512(_hmacKey),
				_ => new HMACSHA256(_hmacKey)
			};

			WarmUpAndGarbageCollecting(hmac, data, 10);

			var stopwatch = new System.Diagnostics.Stopwatch();
			stopwatch.Start();
			for (int i = 0; i < iterations; i++)
			{
				hmac.ComputeHash(data);
			}
			stopwatch.Stop();

			double totalTimeMs = stopwatch.Elapsed.TotalMilliseconds;
			double timePerHashMicroseconds = (totalTimeMs * 1000) / iterations;
			double bytesPerSecond = (inputSize * iterations) / stopwatch.Elapsed.TotalSeconds;
			double mbPerSecond = bytesPerSecond / (1024 * 1024);

			return new HashTestResult
			{
				Algorithm = algorithm,
				InputSize = inputSize,
				Iterations = iterations,
				TotalTimeMs = totalTimeMs,
				TimePerHashMicroseconds = timePerHashMicroseconds,
				ThroughputMBps = mbPerSecond
			};
		});
	}

	private Task<HashTestResult> RunPBKDF2TestAsync(int passwordSize, int iterations)
	{
		return Task.Run(() => {
			byte[] randomBytes = new byte[passwordSize];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(randomBytes);
			}
			string password = Convert.ToBase64String(randomBytes).Substring(0, passwordSize);

			byte[] salt = new byte[16];
			using (var rng = RandomNumberGenerator.Create())
			{
				rng.GetBytes(salt);
			}

			// "Uppvärmning" och garbage-collecting
			for (int i = 0; i < 5; i++)
			{
				Rfc2898DeriveBytes.Pbkdf2(
					password,
					salt,
					_pbkdf2Iterations,
					HashAlgorithmName.SHA256,
					32);
			}
			GC.Collect();
			GC.WaitForPendingFinalizers();

			// "Riktiga" testet
			var stopwatch = new System.Diagnostics.Stopwatch();
			stopwatch.Start();
			for (int i = 0; i < iterations; i++)
			{
				Rfc2898DeriveBytes.Pbkdf2(
					password,
					salt,
					_pbkdf2Iterations,
					HashAlgorithmName.SHA256,
					32);
			}
			stopwatch.Stop();

			double totalTimeMs = stopwatch.Elapsed.TotalMilliseconds;
			double timePerHashMicroseconds = (totalTimeMs * 1000) / iterations;
			double hashesPerSecond = iterations / stopwatch.Elapsed.TotalSeconds;

			return new HashTestResult
			{
				Algorithm = $"PBKDF2 ({_pbkdf2Iterations} iterationer)",
				InputSize = passwordSize,
				Iterations = iterations,
				TotalTimeMs = totalTimeMs,
				TimePerHashMicroseconds = timePerHashMicroseconds,
				ThroughputMBps = hashesPerSecond // För PBKDF2 visar vi hashar per sekund istället för throughput
			};
		});
	}

	private static void WarmUpAndGarbageCollecting(HashAlgorithm algorithm, byte[] data, int iterations)
	{
		for (int i = 0; i < iterations; i++)
		{
			algorithm.ComputeHash(data);
		}
		GC.Collect();
		GC.WaitForPendingFinalizers();
	}
}