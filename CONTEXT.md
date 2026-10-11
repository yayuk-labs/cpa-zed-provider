# Zed Provider

Zed accounts supply access to AI models through Zed Cloud within CLIProxyAPI.

## Language

**Zed credential**: The user ID and opaque credential acquired by signing into Zed. It authorizes acquisition of an LLM token.

**LLM token**: Short-lived authorization for Zed Cloud model discovery and completions.

**Upstream provider**: The service behind a Zed model: Anthropic, OpenAI, Google, or xAI.

**Zed model**: An AI model available to a Zed account. Its upstream provider can be identified by its name or provider prefix.

**Native login callback**: The loopback URL returned by Zed sign-in, containing a user ID and encrypted Zed credential.

**Login session**: A pending sign-in attempt with a unique state, callback address, and expiry.
