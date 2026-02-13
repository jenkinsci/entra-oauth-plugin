package io.jenkins.plugins.entraoauth;

import edu.umd.cs.findbugs.annotations.CheckForNull;
import hudson.Util;
import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

final class ScopeUtils {
    private ScopeUtils() {}

    static List<String> parseScopes(@CheckForNull String raw) {
        if (raw == null) {
            return List.of();
        }
        Set<String> result = new LinkedHashSet<>();
        String[] parts = raw.split("[\\r\\n,]");
        for (String part : parts) {
            String trimmed = Util.fixEmptyAndTrim(part);
            if (trimmed != null) {
                result.add(trimmed);
            }
        }
        return new ArrayList<>(result);
    }
}


