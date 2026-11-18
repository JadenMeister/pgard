// corpus: expect=PG-XSS-001
export const Row = Backbone.View.extend({
  render() {
    this.$el.html("<td>" + location.hash + "</td>");
    return this;
  },
});
