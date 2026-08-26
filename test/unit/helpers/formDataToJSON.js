import assert from 'assert';
import formDataToJSON from '../../../lib/helpers/formDataToJSON.js';
import AxiosError from '../../../lib/core/AxiosError.js';

describe('helpers::formDataToJSON', function () {
  // Node 12/14/16 have no global FormData; the spec-compliant entries() API is
  // required by formDataToJSON, so skip the whole suite on those legs.
  before(function () {
    if (typeof FormData !== 'function') {
      this.skip();
    }
  });

  describe('maxDepth', function () {
    it('should throw AxiosError when a field path exceeds the default depth limit', function () {
      const formData = new FormData();

      formData.append('foo' + '[bar]'.repeat(101), '123');

      try {
        formDataToJSON(formData);
        assert.fail('Should have thrown');
      } catch (err) {
        assert.ok(err instanceof AxiosError, 'error must be AxiosError, not RangeError');
        assert.strictEqual(err.code, AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED);
        assert.ok(!(err instanceof RangeError));
      }
    });

    it('should throw AxiosError while tokenizing very deep field paths', function () {
      const formData = new FormData();

      formData.append('foo' + '[bar]'.repeat(10000), '123');

      try {
        formDataToJSON(formData);
        assert.fail('Should have thrown');
      } catch (err) {
        assert.ok(err instanceof AxiosError, 'error must be AxiosError, not RangeError');
        assert.strictEqual(err.code, AxiosError.ERR_FORM_DATA_DEPTH_EXCEEDED);
        assert.ok(!(err instanceof RangeError));
      }
    });

    it('should convert a field path at the default depth limit', function () {
      const formData = new FormData();

      formData.append('foo' + '[bar]'.repeat(100), '123');

      let value = formDataToJSON(formData).foo;

      for (let i = 0; i < 100; i++) {
        value = value.bar;
      }

      assert.strictEqual(value, '123');
    });
  });
});
