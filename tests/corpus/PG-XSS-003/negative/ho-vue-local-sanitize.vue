<!-- corpus: expect=low -->
<template>
  <article v-html="sanitize($route.query.body)"></article>
</template>
<script setup>
const sanitize = (value) => value;
</script>
