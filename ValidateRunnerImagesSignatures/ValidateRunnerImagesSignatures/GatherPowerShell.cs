using System.Linq;
using System.Management.Automation.Language;
using System.Text;

namespace ValidateRunnerImagesSignatures;

public static class GatherPowerShell
{
    private static readonly StringComparer _comparer = StringComparer.InvariantCultureIgnoreCase;

    private static readonly HashSet<string> _gatheredCommands = new HashSet<string>(_comparer);
    private static readonly HashSet<string> _allowedCommands = new HashSet<string>(_comparer)
    {
        // Commands exchanged with validation commands
        "Install-Binary",
        "Remove-Item",
        "Rename-Item",
        // Modified functions in the scripts
        "Install-DotnetSDK",
        "Install-JavaJDK",
        "Install-Msys2",
        // Safe commands
        "Invoke-DownloadWithRetry",
        "Join-Path",
        "Test-Path",
        "Split-Path",
        "New-Item",
        "Out-Null",
        "Expand-7ZipArchive",
        "Get-ToolsetContent",
        "Invoke-WebRequest",
        "Where-Object",
        "Select-String",
        "ForEach-Object",
        "Invoke-RestMethod",
        "Sort-Object",
        "Test-IsWin19",
        "Test-IsWin22",
        "Resolve-GithubReleaseAssetUrl",
        "Get-ChecksumFromUrl",
        "Test-FileSignature",
        "Test-FileChecksum",
        "Get-Item",
        "Get-Content",
        "Get-ItemProperty",
        "Get-GithubReleasesByVersion",
        "Write-Host",
        "Get-ChecksumFromGithubRelease",
        "ConvertFrom-HTML",
        "Get-Member",
        "Select-Object",
        "Get-AndroidPackages",
        "Get-AndroidPlatformPackages",
        "Get-AndroidBuildToolPackages",
        "Get-SDKVersionsToInstall",
        "ConvertFrom-Json",
        "Group-Object",
        "Invoke-ScriptBlockWithRetry",
        "Get-ChildItem"
    };

    private static readonly HashSet<string> _allowedStaticMemberAccess = new HashSet<string>(_comparer)
    {
        "[System.Diagnostics.FileVersionInfo]::GetVersionInfo",
        "[System.IO.Path]::GetTempPath",
        "[System.IO.Path]::GetRandomFileName"
    };

    private static readonly HashSet<string> _skipCommands = new HashSet<string>(_comparer)
    {
        "Add-MachinePathItem",
        "Out-File",
        "Copy-Item",
        "Install-PyPy",
        "Install-AndroidSDKPackages",
        "Invoke-Expression",        
        "Invoke-DotnetWarmup",
        "Set-JavaPath",
        "Install-Msys2Packages",
        "Install-MingwPackages",
        "Install-VSIXFromFile"
    };

    private static readonly HashSet<string> _skipRawTokenText = new HashSet<string>(_comparer)
    {
        "\"$SDKInstallRoot\\android-sdk-licenses.zip\"",
        "\"ndk;$ndkLatestMajorVersion\"",
        "\"ndk;$ndkDefaultMajorVersion\"",
        "\"C:\\$_\\bin\\mingw32-make.exe\""
    };

    private static readonly Dictionary<string, string> _replacementCommands = new Dictionary<string, string>(_comparer)
    {
        ["Test-IsWin19"] = "$false",
        ["Test-IsWin22"] = "$true",
        ["Install-Binary"] = "Validate-Install-Binary",
        ["Remove-Item"] = "Validate-Remove-Item",
        ["Rename-Item"] = "Validate-Rename-Item"
    };

    private static readonly Dictionary<string, Func<List<Token>, bool>> _searchedTokens = new Dictionary<string, Func<List<Token>, bool>>(_comparer)
    {
        ["Install-Binary"] = tokens => tokens.Any(t => t.Kind == TokenKind.Parameter
            && (t.Text.Equals("-ExpectedSignature", StringComparison.InvariantCultureIgnoreCase)
                || t.Text.Equals("-ExpectedSHA256Sum", StringComparison.InvariantCultureIgnoreCase)
                || t.Text.Equals("-ExpectedSHA512Sum", StringComparison.InvariantCultureIgnoreCase))),
        ["Test-FileSignature"] = _ => true,
        ["Test-FileChecksum"] = _ => true
    };

    public static string GatherScriptParts(string directory)
    {
        var combinedScriptParts = new StringBuilder();

        var psFiles = Directory.GetFiles(directory, "*.ps1", SearchOption.AllDirectories);
        foreach (var psFile in psFiles)
        {
            var scriptBlock = Parser.ParseFile(psFile, out Token[] tokens, out ParseError[] errors);
            var scriptString = File.ReadAllText(psFile);

            var indexedTokens = IndexTokens(tokens, out var commands, out var variableUses);

            foreach (var searchedToken in _searchedTokens)
            {
                if (commands.TryGetValue(searchedToken.Key, out var commandList))
                {
                    foreach (var (line, token) in commandList)
                    {
                        var lineTokens = indexedTokens[line];
                        if (searchedToken.Value(lineTokens) /*&& lineTokens[0].Kind != TokenKind.Function*/)
                        {
                            var matchedToken = indexedTokens[line][token];

                            var relatedScriptParts = GatherRelatedLines(scriptString, indexedTokens, commands, variableUses, line);
                            combinedScriptParts.AppendLine("Write-Host");
                            combinedScriptParts.AppendLine($"Write-Host '{matchedToken.Extent.File}:{matchedToken.Extent.StartLineNumber}:{matchedToken.Extent.StartColumnNumber}' -ForegroundColor Green");
                            combinedScriptParts.AppendLine(relatedScriptParts);
                        }
                    }
                }
            }
        }

        return combinedScriptParts.ToString();
    }

    private static Dictionary<string, HashSet<int>> _alreadyOutputLines = new Dictionary<string, HashSet<int>>();

    public static string GatherRelatedLines(string scriptString,
        List<List<Token>> indexedTokens,
        Dictionary<string, List<(int Line, int Token)>> commands,
        Dictionary<string, List<(int Line, int Token)>> variableUses,
        int line)
    {
        var includedLines = new HashSet<int>();
        var lineQueue = new Queue<int>();
        lineQueue.Enqueue(line);

        while (lineQueue.Count > 0)
        {
            var curLine = lineQueue.Dequeue();
            if (includedLines.Contains(curLine))
            {
                continue;
            }

            includedLines.Add(curLine);

            var lineTokens = indexedTokens[curLine];

            var variables = ExpandStringExpandableTokens(lineTokens)
                .OfType<VariableToken>()
                .Select(t => t.VariablePath.UserPath)
                .ToList();

            foreach (var variable in variables)
            {
                if (variable.StartsWith("env:", StringComparison.InvariantCultureIgnoreCase))
                    continue;

                var declarationLines = variableUses[variable];
                foreach (var (declarationLine, _) in declarationLines)
                {
                    lineQueue.Enqueue(declarationLine);
                }
            }

            var functionName = lineTokens[0].Kind == TokenKind.Function ? lineTokens.FirstOrDefault(t => t.Kind == TokenKind.Generic)?.Text : null;

            if (functionName is not null)
            {
                if (commands.TryGetValue(functionName, out var calls) && !_skipCommands.Contains(functionName))
                {
                    foreach (var (callLine, _) in calls)
                    {
                        if (callLine != curLine)
                            lineQueue.Enqueue(callLine);
                    }
                }
            }
        }

        if (_alreadyOutputLines.TryGetValue(scriptString, out var alreadyOutputLines))
        {
            includedLines = includedLines.Except(alreadyOutputLines).ToHashSet();
            alreadyOutputLines.UnionWith(includedLines);
        }
        else
        {
            _alreadyOutputLines[scriptString] = includedLines;
        }

        var relatedLinesBuilder = new StringBuilder();
        foreach (var relatedLine in includedLines.OrderBy(l => l))
        {
            var lineTokens = indexedTokens[relatedLine];

            var functionName = lineTokens[0].Kind == TokenKind.Function ? lineTokens.FirstOrDefault(t => t.Kind == TokenKind.Generic)?.Text : null;
            if (functionName is not null && _skipCommands.Contains(functionName))
                continue;

            lineTokens = RemoveSkippedLines(lineTokens);
            if (lineTokens.Count == 0 /*|| lineTokens[0].Kind == TokenKind.Function*/)
                continue;

            var invalidToken = lineTokens.FirstOrDefault(t => t.Kind == TokenKind.Generic && t.TokenFlags == TokenFlags.CommandName && !_allowedCommands.Contains(t.Text));
            if (invalidToken is not null)
                throw new InvalidOperationException($"Found a command '{invalidToken.Text}' that is not allowed in the script.");

            var token = lineTokens[0];
            HandleToken(relatedLinesBuilder, token);
            for (var i = 1; i < lineTokens.Count; ++i)
            {
                var whitespace = scriptString.Substring(token.Extent.EndOffset, lineTokens[i].Extent.StartOffset - token.Extent.EndOffset);
                if (string.IsNullOrWhiteSpace(whitespace))
                    relatedLinesBuilder.Append(whitespace);

                token = lineTokens[i];
                HandleToken(relatedLinesBuilder, token);
            }
        }

        return relatedLinesBuilder.ToString();
    }

    private static List<Token> RemoveSkippedLines(List<Token> lineTokens)
    {
        var hasSkipToken = lineTokens.Any(SkipToken);
        if (hasSkipToken)
        {
            var newLineTokens = new List<Token>();
            var curLine = new List<Token>();
            var skipCurLine = false;
            var openParenCount = 0;
            foreach (var token in lineTokens)
            {
                if (token.Kind == TokenKind.LParen || token.Kind == TokenKind.AtParen || token.Kind == TokenKind.DollarParen)
                {
                    openParenCount++;
                }
                else if (token.Kind == TokenKind.RParen)
                {
                    openParenCount--;
                    if (openParenCount < 0) throw new InvalidOperationException("Unbalanced parenthesis.");
                }

                if (SkipToken(token))
                {
                    curLine.Add(token);
                    skipCurLine = true;
                }
                else if ((token.Kind == TokenKind.LCurly || token.Kind == TokenKind.RCurly) && openParenCount == 0)
                {
                    if (!skipCurLine)
                        newLineTokens.AddRange(curLine);

                    skipCurLine = false;
                    curLine.Clear();

                    curLine.Add(token);
                }
                else if (token.Kind == TokenKind.NewLine)
                {
                    curLine.Add(token);

                    if (!skipCurLine)
                        newLineTokens.AddRange(curLine);

                    skipCurLine = false;
                    curLine.Clear();
                }
                else
                {
                    curLine.Add(token);
                }
            }
            newLineTokens.AddRange(curLine);

            return newLineTokens;
        }

        return lineTokens;

        bool SkipToken(Token token)
        {
            if (token.Kind == TokenKind.Generic && token.TokenFlags == TokenFlags.CommandName && _skipCommands.Contains(token.Text))
                return true;

            if (token.Kind == TokenKind.Ampersand)
                return true;

            if (token.Kind == TokenKind.ColonColon && !_allowedStaticMemberAccess.Any(allowed => token.Extent.StartScriptPosition.Line.Contains(allowed, StringComparison.InvariantCultureIgnoreCase)))
                return true;

            if (token.Kind == TokenKind.Identifier && token.TokenFlags == TokenFlags.CommandName)
                return true;

            if (_skipRawTokenText.Contains(token.Text))
                return true;

            return false;
        }
    }

    private static void HandleToken(StringBuilder relatedLinesBuilder, Token token)
    {
        if (token.Kind == TokenKind.Generic && token.TokenFlags == TokenFlags.CommandName)
        {
            _gatheredCommands.Add(token.Text);

            if (_replacementCommands.TryGetValue(token.Text, out var replacement))
            {
                relatedLinesBuilder.Append(replacement);
                return;
            }
        }

        relatedLinesBuilder.Append(token.Text);
    }

    private static List<Token> ExpandStringExpandableTokens(List<Token> tokens)
    {
        return tokens.SelectMany(Expand).ToList();
    }

    private static IEnumerable<Token> Expand(Token token)
    {
        if (token is StringExpandableToken stringExpandableToken)
        {
            var nestedTokens = stringExpandableToken.NestedTokens;
            return nestedTokens is null
                ? [ token ]
                : nestedTokens.SelectMany(Expand);
        }

        return [ token ];
    }

    public static List<List<Token>> IndexTokens(Token[] tokens,
        out Dictionary<string, List<(int Line, int Token)>> commands,
        out Dictionary<string, List<(int Line, int Token)>> variableUses)
    {
        var lineSplitTokens = new List<List<Token>>();

        commands = new Dictionary<string, List<(int Line, int Token)>>(_comparer);
        variableUses = new Dictionary<string, List<(int Line, int Token)>>(_comparer);

        var openBraceCount = 0;
        var openParenCount = 0;
        var openBracketCount = 0;
        var curSplit = new List<Token>();
        for (var i = 0; i < tokens.Length; ++i)
        {
            var token = tokens[i];
            if (token.Kind == TokenKind.NewLine && openBraceCount == 0 && openParenCount == 0 && openBracketCount == 0)
            {
                curSplit.Add(token);
                lineSplitTokens.Add(curSplit);
                curSplit = new List<Token>();
            }
            else
            {
                curSplit.Add(token);

                if (token.Kind == TokenKind.LCurly || token.Kind == TokenKind.AtCurly)
                {
                    openBraceCount++;
                }
                else if (token.Kind == TokenKind.RCurly)
                {
                    openBraceCount--;
                    if (openBraceCount < 0) throw new InvalidOperationException("Unbalanced curly braces.");
                }
                else if (token.Kind == TokenKind.LParen || token.Kind == TokenKind.AtParen || token.Kind == TokenKind.DollarParen)
                {
                    openParenCount++;
                }
                else if (token.Kind == TokenKind.RParen)
                {
                    openParenCount--;
                    if (openParenCount < 0) throw new InvalidOperationException("Unbalanced parenthesis.");
                }
                else if (token.Kind == TokenKind.LBracket)
                {
                    openBracketCount++;
                }
                else if (token.Kind == TokenKind.RBracket)
                {
                    openBracketCount--;
                    if (openBracketCount < 0) throw new InvalidOperationException("Unbalanced square braces.");
                }

                if (token.Kind == TokenKind.Generic && token.TokenFlags == TokenFlags.CommandName)
                {
                    if (!commands.TryGetValue(token.Text, out var commandList))
                    {
                        commandList = new List<(int Line, int Token)>();
                        commands[token.Text] = commandList;
                    }
                    
                    commandList.Add((lineSplitTokens.Count, curSplit.Count - 1));
                }

                if (token is VariableToken variableToken)
                {
                    if (!variableUses.TryGetValue(variableToken.Name, out var variableList))
                    {
                        variableList = new List<(int Line, int Token)>();
                        variableUses[variableToken.Name] = variableList;
                    }

                    variableList.Add((lineSplitTokens.Count, curSplit.Count - 2));
                }
            }
        }

        if (curSplit.Count > 0)
        {
            lineSplitTokens.Add(curSplit);
        }

        return lineSplitTokens;
    }
}
