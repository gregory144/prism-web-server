#ifndef H2_ERROR_H
#define H2_ERROR_H

/**
 * HTTP 2 errors
 */
enum h2_error_code_e {

  /**
   * The associated condition is not as a result of an error. For example, a
   * GOAWAY might include this code to indicate graceful shutdown of a connection.
   */
  H2_ERROR_NO_ERROR,

  /**
   * The endpoint detected an unspecific protocol error. This error is for use
   * when a more specific error code is not available.
   */
  H2_ERROR_PROTOCOL_ERROR,

  /**
   * The endpoint encountered an unexpected internal error.
   */
  H2_ERROR_INTERNAL_ERROR,

  /**
   * The endpoint detected that its peer violated the flow control protocol.
   */
  H2_ERROR_FLOW_CONTROL_ERROR,

  /**
   * The endpoint sent a SETTINGS frame, but did not receive a response in a
   * timely manner. See Settings Synchronization (Section 6.5.3).
   */
  H2_ERROR_SETTINGS_TIMEOUT,

  /**
   * The endpoint received a frame after a stream was half closed.
   */
  H2_ERROR_STREAM_CLOSED,

  /**
   * The endpoint received a frame that was larger than the maximum size
   * that it supports.
   */
  H2_ERROR_FRAME_SIZE_ERROR,

  /**
   * The endpoint refuses the stream prior to performing any application
   * processing, see Section 8.1.4 for details.
   */
  H2_ERROR_REFUSED_STREAM,

  /**
   * Used by the endpoint to indicate that the stream is no longer needed.
   */
  H2_ERROR_CANCEL,

  /**
   * The endpoint is unable to maintain the compression context for the
   * connection.
   */
  H2_ERROR_COMPRESSION_ERROR,

  /**
   * The connection established in response to a CONNECT request (Section 8.3)
   * was reset or abnormally closed.
   */
  H2_ERROR_CONNECT_ERROR,

  /**
   * The endpoint detected that its peer is exhibiting a behavior over a given
   * amount of time that has caused it to refuse to process further frames.
   */
  H2_ERROR_ENHANCE_YOUR_CALM,

  /**
   * The underlying transport has properties that do not meet the minimum
   * requirements imposed by this document (see Section 9.2) or the endpoint.
   */
  H2_ERROR_INADEQUATE_SECURITY

};

const char * h2_error_to_string(enum h2_error_code_e code);

#endif
